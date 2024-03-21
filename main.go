package main

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/frida/frida-go/frida"
	"github.com/spf13/cobra"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
)

//go:embed script.js
var scContent string

var Version string

var rootCmd = &cobra.Command{
	Use:     "gxpc [spawn_args]",
	Short:   "XPC sniffer",
	Version: Version,
	Run: func(cmd *cobra.Command, args []string) {
		logger := NewLogger()

		list, err := cmd.Flags().GetBool("list")
		if err != nil {
			logger.Errorf("%v", err)
			return
		}

		id, err := cmd.Flags().GetString("id")
		if err != nil {
			logger.Errorf("%v", err)
			return
		}

		remote, err := cmd.Flags().GetString("remote")
		if err != nil {
			logger.Errorf("%v", err)
			return
		}

		pid, err := cmd.Flags().GetInt("pid")
		if err != nil {
			logger.Errorf("%v", err)
			return
		}

		procName, err := cmd.Flags().GetString("name")
		if err != nil {
			logger.Errorf("%v", err)
			return
		}

		output, err := cmd.Flags().GetString("output")
		if err != nil {
			logger.Errorf("%v", err)
			return
		}

		if output != "" {
			if err := logger.SetOutput(output); err != nil {
				logger.Errorf("%v", err)
				return
			}
		}

		defer logger.Close()

		mgr := frida.NewDeviceManager()
		devices, err := mgr.EnumerateDevices()
		if err != nil {
			logger.Errorf("%v", err)
			return
		}

		if list {
			for _, d := range devices {
				logger.Infof("[%s]\t%s (%s)\n",
					strings.ToUpper(d.DeviceType().String()),
					d.Name(),
					d.ID())
			}
			return
		}

		var dev *frida.Device
		var session *frida.Session

		for _, d := range devices {
			if id != "" {
				if d.ID() == id {
					dev = d
					break
				}
			} else if remote != "" {
				rdevice, err := mgr.AddRemoteDevice(remote, nil)
				if err != nil {
					logger.Errorf("%v", err)
					return
				}
				dev = rdevice
				break
			} else {
				dev = frida.USBDevice()
			}
		}

		if dev == nil {
			logger.Errorf("Could not obtain specified device")
			return
		}
		defer dev.Clean()
		logger.Infof("Using device %s (%s)", dev.Name(), dev.ID())

		procPid := pid

		if pid == -1 && procName != "" {
			processes, err := dev.EnumerateProcesses(frida.ScopeMinimal)
			if err != nil {
				logger.Errorf("Error enumerating processes: %v", err)
				return
			}

			for _, proc := range processes {
				if proc.Name() == procName {
					procPid = proc.PID()
					break
				}
			}
		}

		file, err := cmd.Flags().GetString("file")
		if err != nil {
			logger.Errorf("%v", err)
			return
		}

		if procPid == -1 && file == "" {
			logger.Errorf("You need to pass pid, name or file to spawn")
			return
		}

		spawned := false

		if procPid != -1 {
			session, err = dev.Attach(procPid, nil)
			if err != nil {
				logger.Errorf("Error attaching: %v", err)
				return
			}
		} else {
			opts := frida.NewSpawnOptions()
			argv := make([]string, len(args)+1)
			argv[0] = file
			for i, arg := range args {
				argv[i+1] = arg
			}
			opts.SetArgv(argv)
			spawnedPID, err := dev.Spawn(file, opts)
			if err != nil {
				logger.Errorf("Error spawning %s: %v", file, err)
				return
			}
			procPid = spawnedPID
			session, err = dev.Attach(spawnedPID, nil)
			if err != nil {
				logger.Errorf("Error attaching: %v", err)
				return
			}
			spawned = true
		}
		defer session.Clean()

		logger.Infof("Attached to the process with PID => %d", procPid)

		detached := make(chan struct{})

		session.On("detached", func(reason frida.SessionDetachReason, crash *frida.Crash) {
			logger.Errorf("Session detached: %s: %v", reason.String(), crash)
			if crash != nil {
				logger.Errorf("Crash: %s %s", crash.Report(), crash.Summary())
			}
			detached <- struct{}{}
		})

		script, err := session.CreateScript(scContent)
		if err != nil {
			logger.Errorf("Error creating script: %v", err)
			return
		}
		defer script.Clean()

		blacklist, err := cmd.Flags().GetStringSlice("blacklist")
		if err != nil {
			logger.Errorf("%v", err)
			return
		}

		whitelist, err := cmd.Flags().GetStringSlice("whitelist")
		if err != nil {
			logger.Errorf("%v", err)
			return
		}

		blacklistp, err := cmd.Flags().GetStringSlice("blacklistp")
		if err != nil {
			logger.Errorf("%v", err)
			return
		}

		whitelistp, err := cmd.Flags().GetStringSlice("whitelist")
		if err != nil {
			logger.Errorf("%v", err)
			return
		}

		script.On("message", func(message string) {
			msg, _ := frida.ScriptMessageToMessage(message)
			switch msg.Type {
			case frida.MessageTypeSend:
				payload := msg.Payload.(map[string]any)

				subType := payload["type"].(string)
				subPayload := payload["payload"]

				switch subType {
				case "print":
					PrintData(
						subPayload,
						false,
						false,
						listToRegex(whitelist),
						listToRegex(blacklist),
						listToRegex(whitelistp),
						listToRegex(blacklistp),
						logger,
					)

				case "jlutil":
					resPayload, err := jlutil(subPayload.(string))
					if err != nil {
						logger.Errorf("jlutil: %v", err)
					}

					msg := fmt.Sprintf(`{"type":"jlutil","payload":"%s"}`, resPayload)
					script.Post(msg, nil)

				default:
					logger.Warnf("SCRIPT: %v", msg)
				}

			case frida.MessageTypeLog:
				logger.Infof("SCRIPT: %v", msg)
			default:
				logger.Errorf("SCRIPT: %v", msg)
			}
		})

		if err := script.Load(); err != nil {
			logger.Errorf("Error loading script: %v", err)
			return
		}
		logger.Infof("Loaded script to the process")

		if spawned {
			if err := dev.Resume(procPid); err != nil {
				logger.Errorf("Error resuming: %v", err)
				return
			} else {
				logger.Infof("Resumed process")
			}
		}

		c := make(chan os.Signal)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)

		select {
		case <-c:
			fmt.Println()
			logger.Infof("Exiting...")
			if err := script.Unload(); err != nil {
				logger.Errorf("Error unloading script: %v", err)
				return
			}
			logger.Infof("Script unloaded")
		case <-detached:
			logger.Infof("Exiting...")
		}
	},
}

func jlutil(payload string) (string, error) {
	decodedPayload, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return "", err
	}

	f, err := os.CreateTemp(os.TempDir(), "")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(decodedPayload); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}

	output, err := exec.Command("jlutil", f.Name()).CombinedOutput()
	if err != nil {
		return "", err
	}

	encodedOutput, err := json.Marshal(string(output))
	if err != nil {
		return "", err
	}

	return string(encodedOutput[1 : len(encodedOutput)-1]), nil
}

func listToRegex(ls []string) []*regexp.Regexp {
	rex := make([]*regexp.Regexp, len(ls))
	for i, item := range ls {
		replaced := strings.ReplaceAll(item, "*", ".*")
		r := regexp.MustCompile(replaced)
		rex[i] = r
	}
	return rex
}

func main() {
	rootCmd.Flags().StringP("id", "i", "", "connect to device with ID")
	rootCmd.Flags().StringP("remote", "r", "", "connect to device at IP address")
	rootCmd.Flags().StringP("name", "n", "", "process name")
	rootCmd.Flags().StringP("file", "f", "", "spawn the file")
	rootCmd.Flags().StringP("output", "o", "", "save output to this file")

	rootCmd.Flags().StringSliceP("whitelist", "w", []string{}, "whitelist connection by name")
	rootCmd.Flags().StringSliceP("blacklist", "b", []string{}, "blacklist connection by name")
	rootCmd.Flags().StringSliceP("whitelistp", "", []string{}, "whitelist connection by PID")
	rootCmd.Flags().StringSliceP("blacklistp", "", []string{}, "blacklist connection by PID")

	rootCmd.Flags().BoolP("list", "l", false, "list available devices")
	//rootCmd.Flags().BoolP("decode", "d", true, "try to decode(bplist00 or bplist15), otherwise print base64 of bytes")
	//rootCmd.Flags().BoolP("hex", "x", false, "print hexdump of raw data")

	rootCmd.Flags().IntP("pid", "p", -1, "PID of wanted process")

	rootCmd.Execute()
}
