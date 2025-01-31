package lxd

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	ctestutil "github.com/hashicorp/nomad/client/testutil"
	"github.com/hashicorp/nomad/helper/testlog"
	"github.com/hashicorp/nomad/helper/uuid"
	"github.com/hashicorp/nomad/nomad/structs"
	"github.com/hashicorp/nomad/plugins/drivers"
	dtestutil "github.com/hashicorp/nomad/plugins/drivers/testutils"
	"github.com/hashicorp/nomad/testutil"
	lxc "github.com/lxc/go-lxc"
	"github.com/stretchr/testify/require"
)

func TestLXCDriver_Fingerprint(t *testing.T) {
	t.Parallel()
	requireLXC(t)

	require := require.New(t)

	d := NewLXDDriver(testlog.HCLogger(t)).(*Driver)
	d.config.Enabled = true
	d.config.NetworkMode = "host"
	harness := dtestutil.NewDriverHarness(t, d)

	fingerCh, err := harness.Fingerprint(context.Background())
	require.NoError(err)
	select {
	case finger := <-fingerCh:
		require.Equal(drivers.HealthStateHealthy, finger.Health)
		require.True(finger.Attributes["driver.lxc"].GetBool())
		require.NotEmpty(finger.Attributes["driver.lxc.version"].GetString())
	case <-time.After(time.Duration(testutil.TestMultiplier()*5) * time.Second):
		require.Fail("timeout receiving fingerprint")
	}
}

func TestLXCDriver_FingerprintNotEnabled(t *testing.T) {
	t.Parallel()
	requireLXC(t)

	require := require.New(t)

	d := NewLXDDriver(testlog.HCLogger(t)).(*Driver)
	d.config.Enabled = false
	d.config.NetworkMode = "host"
	harness := dtestutil.NewDriverHarness(t, d)

	fingerCh, err := harness.Fingerprint(context.Background())
	require.NoError(err)
	select {
	case finger := <-fingerCh:
		require.Equal(drivers.HealthStateUndetected, finger.Health)
		require.Empty(finger.Attributes["driver.lxc"])
		require.Empty(finger.Attributes["driver.lxc.version"])
	case <-time.After(time.Duration(testutil.TestMultiplier()*5) * time.Second):
		require.Fail("timeout receiving fingerprint")
	}
}

func TestLXCDriver_Start_Wait(t *testing.T) {
	if !testutil.IsTravis() {
		t.Parallel()
	}
	requireLXC(t)
	ctestutil.RequireRoot(t)

	require := require.New(t)

	// prepare test file
	testFileContents := []byte("this should be visible under /mnt/tmp")
	tmpFile, err := ioutil.TempFile("/tmp", "testlxcdriver_start_wait")
	if err != nil {
		t.Fatalf("error writing temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	if _, err := tmpFile.Write(testFileContents); err != nil {
		t.Fatalf("error writing temp file: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("error closing temp file: %v", err)
	}

	d := NewLXDDriver(testlog.HCLogger(t)).(*Driver)
	d.config.Enabled = true
	d.config.AllowVolumes = true
	d.config.NetworkMode = "host"

	harness := dtestutil.NewDriverHarness(t, d)
	task := &drivers.TaskConfig{
		ID:      uuid.Generate(),
		AllocID: uuid.Generate(),
		Name:    "test",
		Resources: &drivers.Resources{
			NomadResources: &structs.AllocatedTaskResources{
				Memory: structs.AllocatedMemoryResources{
					MemoryMB: 2,
				},
				Cpu: structs.AllocatedCpuResources{
					CpuShares: 1024,
				},
			},
			LinuxResources: &drivers.LinuxResources{
				CPUShares:        1024,
				MemoryLimitBytes: 2 * 1024,
			},
		},
	}
	taskConfig := map[string]interface{}{
		"template": "/usr/share/lxc/templates/lxc-busybox",
		"volumes":  []string{"/tmp/:mnt/tmp"},
	}
	require.NoError(task.EncodeConcreteDriverConfig(&taskConfig))

	cleanup := harness.MkAllocDir(task, false)
	defer cleanup()

	handle, _, err := harness.StartTask(task)
	require.NoError(err)
	require.NotNil(handle)

	lxcHandle, ok := d.tasks.Get(task.ID)
	require.True(ok)

	container := lxcHandle.container

	// Destroy container after test
	defer func() {
		err := container.Stop()
		if err != nil {
			fmt.Println("container could not be stopped")
		}
		err = container.Destroy()
		if err != nil {
			fmt.Println("container could not be destroyed")
		}
	}()

	// Test that container is running
	testutil.WaitForResult(func() (bool, error) {
		state := container.State()
		if state == lxc.RUNNING {
			return true, nil
		}
		return false, fmt.Errorf("container in state: %v", state)
	}, func(err error) {
		t.Fatalf("container failed to start: %v", err)
	})

	// Test that directories are mounted in their proper location
	containerName := container.Name()
	for _, mnt := range []string{"alloc", "local", "secrets", "mnt/tmp"} {
		fullpath := filepath.Join(d.lxcPath(), containerName, "rootfs", mnt)
		stat, err := os.Stat(fullpath)
		require.NoError(err)
		require.True(stat.IsDir())
	}

	// Test bind mount volumes exist in container:
	mountedContents, err := exec.Command("lxc-attach",
		"-n", containerName, "--",
		"cat", filepath.Join("/mnt/", tmpFile.Name()),
	).Output()
	require.NoError(err)
	require.Equal(string(testFileContents), string(mountedContents))

	// Test that killing container marks container as stopped
	require.NoError(container.Stop())

	testutil.WaitForResult(func() (bool, error) {
		status, err := d.InspectTask(task.ID)
		if err == nil && status.State == drivers.TaskStateExited {
			return true, nil
		}
		return false, fmt.Errorf("task in state: %v", status.State)
	}, func(err error) {
		t.Fatalf("task was not marked as stopped: %v", err)
	})
}

func TestLXCDriver_Start_Stop(t *testing.T) {
	if !testutil.IsTravis() {
		t.Parallel()
	}
	requireLXC(t)
	ctestutil.RequireRoot(t)

	require := require.New(t)

	d := NewLXDDriver(testlog.HCLogger(t)).(*Driver)
	d.config.Enabled = true
	d.config.AllowVolumes = true
	d.config.NetworkMode = "host"

	harness := dtestutil.NewDriverHarness(t, d)
	task := &drivers.TaskConfig{
		ID:      uuid.Generate(),
		AllocID: uuid.Generate(),
		Name:    "test",
		Resources: &drivers.Resources{
			NomadResources: &structs.AllocatedTaskResources{
				Memory: structs.AllocatedMemoryResources{
					MemoryMB: 2,
				},
				Cpu: structs.AllocatedCpuResources{
					CpuShares: 1024,
				},
			},
			LinuxResources: &drivers.LinuxResources{
				CPUShares:        1024,
				MemoryLimitBytes: 2 * 1024,
			},
		},
	}
	taskConfig := map[string]interface{}{
		"template": "/usr/share/lxc/templates/lxc-busybox",
	}
	require.NoError(task.EncodeConcreteDriverConfig(&taskConfig))

	cleanup := harness.MkAllocDir(task, false)
	defer cleanup()

	handle, _, err := harness.StartTask(task)
	require.NoError(err)
	require.NotNil(handle)

	lxcHandle, ok := d.tasks.Get(task.ID)
	require.True(ok)

	container := lxcHandle.container

	// Destroy container after test
	defer func() {
		err := container.Stop()
		if err != nil {
			fmt.Println("container could not be stopped")
		}
		err = container.Destroy()
		if err != nil {
			fmt.Println("container could not be destroyed")
		}
	}()

	// Test that container is running
	testutil.WaitForResult(func() (bool, error) {
		state := container.State()
		if state == lxc.RUNNING {
			return true, nil
		}
		return false, fmt.Errorf("container in state: %v", state)
	}, func(err error) {
		t.Fatalf("container failed to start: %v", err)
	})

	require.NoError(d.StopTask(task.ID, 5*time.Second, "kill"))

	testutil.WaitForResult(func() (bool, error) {
		status, err := d.InspectTask(task.ID)
		if err == nil && status.State == drivers.TaskStateExited {
			return true, nil
		}
		return false, fmt.Errorf("task in state: %v", status.State)
	}, func(err error) {
		t.Fatalf("task was not marked as stopped: %v", err)
	})
}

// check if lxc container is destroyed if gc.container=true
func TestLXCDriver_GC_Container_on(t *testing.T) {
	if !testutil.IsTravis() {
		t.Parallel()
	}
	requireLXC(t)
	ctestutil.RequireRoot(t)

	require := require.New(t)

	d := NewLXDDriver(testlog.HCLogger(t)).(*Driver)
	d.config.Enabled = true
	d.config.NetworkMode = "host"
	// enable Container GC
	d.config.GC.Container = true

	harness := dtestutil.NewDriverHarness(t, d)
	task := &drivers.TaskConfig{
		ID:      uuid.Generate(),
		AllocID: uuid.Generate(),
		Name:    "test",
		Resources: &drivers.Resources{
			NomadResources: &structs.AllocatedTaskResources{
				Memory: structs.AllocatedMemoryResources{
					MemoryMB: 2,
				},
				Cpu: structs.AllocatedCpuResources{
					CpuShares: 1024,
				},
			},
			LinuxResources: &drivers.LinuxResources{
				CPUShares:        1024,
				MemoryLimitBytes: 2 * 1024,
			},
		},
	}
	taskConfig := map[string]interface{}{
		"template": "/usr/share/lxc/templates/lxc-busybox",
	}
	require.NoError(task.EncodeConcreteDriverConfig(&taskConfig))

	cleanup := harness.MkAllocDir(task, false)
	defer cleanup()

	handle, _, err := harness.StartTask(task)
	require.NoError(err)
	require.NotNil(handle)

	lxcHandle, ok := d.tasks.Get(task.ID)
	require.True(ok)

	container := lxcHandle.container

	// Destroy container after test
	defer func() {
		err := container.Stop()
		if err != nil {
			fmt.Println("container could not be stopped")
		}
		err = container.Destroy()
		if err != nil {
			fmt.Println("container could not be destroyed")
		}
	}()

	// Test that container is running
	testutil.WaitForResult(func() (bool, error) {
		state := container.State()
		if state == lxc.RUNNING {
			return true, nil
		}
		return false, fmt.Errorf("container in state: %v", state)
	}, func(err error) {
		t.Fatalf("container failed to start: %v", err)
	})

	lxcContainerName := container.Name()

	// stop task
	require.NoError(harness.StopTask(task.ID, 0, ""))
	require.NoError(harness.DestroyTask(task.ID, true))

	require.False(containerExists(lxcContainerName))
}

// check if lxc container is not destroyed if gc.container=false
func TestLXCDriver_GC_Container_off(t *testing.T) {
	if !testutil.IsTravis() {
		t.Parallel()
	}
	requireLXC(t)
	ctestutil.RequireRoot(t)

	require := require.New(t)

	d := NewLXDDriver(testlog.HCLogger(t)).(*Driver)
	d.config.Enabled = true
	d.config.NetworkMode = "host"
	// disable Container GC
	d.config.GC.Container = false

	harness := dtestutil.NewDriverHarness(t, d)
	task := &drivers.TaskConfig{
		ID:      uuid.Generate(),
		AllocID: uuid.Generate(),
		Name:    "test",
		Resources: &drivers.Resources{
			NomadResources: &structs.AllocatedTaskResources{
				Memory: structs.AllocatedMemoryResources{
					MemoryMB: 2,
				},
				Cpu: structs.AllocatedCpuResources{
					CpuShares: 1024,
				},
			},
			LinuxResources: &drivers.LinuxResources{
				CPUShares:        1024,
				MemoryLimitBytes: 2 * 1024,
			},
		},
	}
	taskConfig := map[string]interface{}{
		"template": "/usr/share/lxc/templates/lxc-busybox",
	}
	require.NoError(task.EncodeConcreteDriverConfig(&taskConfig))

	cleanup := harness.MkAllocDir(task, false)
	defer cleanup()

	handle, _, err := harness.StartTask(task)
	require.NoError(err)
	require.NotNil(handle)

	lxcHandle, ok := d.tasks.Get(task.ID)
	require.True(ok)

	container := lxcHandle.container

	// Destroy container after test
	defer func() {
		err := container.Stop()
		if err != nil {
			fmt.Println("container could not be stopped")
		}
		err = container.Destroy()
		if err != nil {
			fmt.Println("container could not be destroyed")
		}
	}()

	// Test that container is running
	testutil.WaitForResult(func() (bool, error) {
		state := container.State()
		if state == lxc.RUNNING {
			return true, nil
		}
		return false, fmt.Errorf("container in state: %v", state)
	}, func(err error) {
		t.Fatalf("container failed to start: %v", err)
	})

	lxcContainerName := container.Name()

	// stop task
	require.NoError(harness.StopTask(task.ID, 0, ""))
	require.NoError(harness.DestroyTask(task.ID, true))

	// container should not be deleted now (GC.Container = false)
	require.True(containerExists(lxcContainerName))
}

func containerExists(containerName string) bool {
	allContainers := lxc.ContainerNames(lxc.DefaultConfigPath())
	for _, name := range allContainers {
		if name == containerName {
			return true
		}
	}
	return false
}

func requireLXC(t *testing.T) {
	if lxc.Version() == "" {
		t.Skip("skipping, lxc not present")
	}
}
