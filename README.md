# gxpc

Alternative to [xpcspy](#) tool which basically uses the same technique except this one is written using 
Go and also uses [frida-go](https://github.com/frida/frida-go) bindings.

# Installation

* Follow the instructions documented [here](https://github.com/frida/frida-go)
* Run `go install github.com/nsecho/gxpc@latest`

# Usage

```bash
$ gxpc --help
XPC sniffer

Usage:
  gxpc [flags]

Flags:
  -d, --decode          try to decode(bplist00 or bplist15), otherwise print base64 of bytes (default true)
  -h, --help            help for gxpc
  -x, --hex             print hex of raw data
  -i, --id string       connect to device with ID
  -l, --list            list available devices
  -n, --name string     process name
  -p, --pid int         PID of wanted process (default -1)
  -r, --remote string   connect to device at IP address
```

![Running gxpc](running.png)

![Running against Signal](running_one.png)

If you do not pass `-i` flag, by default it will use USB device.

Also, if `-d` flag is set up it will try to parse `plists` like `bplist00` and `bplist15`, otherwise just base64 representation 
of raw bytes will be returned. You can also use `-x` flag to get hexadecimal representation of raw bytes. Strings will be shown as strings 
without any encoding.