# gxpc

Alternative to [xpcspy](https://github.com/hot3eed/xpcspy) tool which basically uses the same technique except this one is written using 
Go using [frida-go](https://github.com/frida/frida-go) bindings.

Additionally, it recursively parses types of `xpc_object_t` as well as unmarshalling the data back to Go types.

# Installation

* Follow the instructions for devkit documented [here](https://github.com/frida/frida-go)
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