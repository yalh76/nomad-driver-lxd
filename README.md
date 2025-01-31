NOT working Nomad LXD Driver, it's Nomad LXC Driver + some changes for [nomad_ynh switch lxc to lxd tests](https://github.com/YunoHost-Apps/nomad_ynh/pull/2)
==================

- Website: https://www.nomadproject.io
- Mailing list: [Google Groups](http://groups.google.com/group/nomad-tool)

Requirements
------------

- [Nomad](https://www.nomadproject.io/downloads.html) 0.9+
- [Go](https://golang.org/doc/install) 1.15+ (to build the provider plugin)
- Linux host with `liblxc` and `lxc-templates` packages installed

Building The Driver
---------------------

Clone repository to: `$GOPATH/src/github.com/yalh76/nomad-driver-lxd`

```sh
$ mkdir -p $GOPATH/src/github.com/yalh76; cd $GOPATH/src/github.com/yalh76
$ git clone git@github.com:yalh76/nomad-driver-lxd
```

Enter the provider directory and build the provider

```sh
$ cd $GOPATH/src/github.com/yalh76/nomad-driver-lxd
$ make build
```

Using the driver
----------------------

- [Documentation](https://www.nomadproject.io/docs/drivers/external/lxd.html)
- [Guide](https://www.nomadproject.io/guides/external/lxd.html)

Developing the Provider
---------------------------

If you wish to work on the driver, you'll first need [Go](http://www.golang.org) installed on your machine, and have have `lxc-dev` and `lxc-templates` packages installed. You'll also need to correctly setup a [GOPATH](http://golang.org/doc/code.html#GOPATH), as well as adding `$GOPATH/bin` to your `$PATH`.

To compile the provider, run `make build`. This will build the provider and put the provider binary in the `$GOPATH/bin` directory.

```sh
$ make build
```

In order to test the provider, you can simply run `make test`.

```sh
$ make test
```
