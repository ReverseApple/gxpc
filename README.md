# gxpc

Tool inspired by [xpcspy](https://github.com/hot3eed/xpcspy) tool to monitor XPC traffic. 

gxpc recursively parses types of `xpc_object_t` as well as unmarshalling the data back to Go types.

# Installation

Download one of the prebuilt binaries for macOS(x86_64 or arm64) from [here](https://github.com/ReverseApple/gxpc/releases) 
or do it manually as described below. 

* Follow the instructions for devkit documented [here](https://github.com/frida/frida-go)
* Run `go install github.com/nsecho/gxpc@latest`

# Usage

```bash
XPC sniffer

Usage:
  gxpc [spawn_args] [flags]

Flags:
  -b, --blacklist strings    blacklist connection by name
      --blacklistp strings   blacklist connection by PID
  -f, --file string          spawn the file
  -h, --help                 help for gxpc
  -i, --id string            connect to device with ID
  -l, --list                 list available devices
  -n, --name string          process name
  -o, --output string        save output to this file
  -p, --pid int              PID of wanted process (default -1)
  -r, --remote string        connect to device at IP address
  -w, --whitelist strings    whitelist connection by name
      --whitelistp strings   whitelist connection by PID
```

If you do not pass `-i` flag, default device is USB.

If you want to spawn a file/binary, pass the `-f` that points to the file/binary you want to spawn along with the arguments.

* `gxpc -i local -f /bin/cat /tmp/somefile` - without some specific flags to the spawned binary
* `gxpc -i local -f /path/to/binary -- -a -b "TEST"` - with some specific flags to the spawned binary

Additionally, you can filter on connection names or PIDs, if you pass both filters (name and PID), it will take only name. 
`--whitelist` and `--whitelistp` along with the `--blacklist` and `--blacklistp` accepts the list, such as `--blacklistp "89,32,41"` which will 
blacklist the ports 89, 32 and 41.

![Running gxpc](running.png)

![Running against Signal](running_one.png)
