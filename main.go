package main

import (
	// TODO: update the path below to match your own repository
	"github.com/yalh76/nomad-driver-lxd/lxc"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/plugins"
)

func main() {
	// Serve the plugin
	plugins.Serve(factory)
}

// factory returns a new instance of the LXD driver plugin
func factory(log hclog.Logger) interface{} {
	return lxd.NewLXDDriver(log)
}
