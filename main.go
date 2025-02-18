package main

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/frida/frida-go/frida"
	"github.com/spf13/cobra"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

//go:embed script.js
var scContent string

var Version string

var logger *Logger = nil

var rootCmd = &cobra.Command{
	Use:           "gxpc [spawn_args]",
	Short:         "XPC sniffer",
	Version:       Version,
	SilenceErrors: true,
	SilenceUsage:  true,
	RunE: func(cmd *cobra.Command, args []string) error {

		initConfig, err := cmd.Flags().GetBool("init")
		if err != nil {
			return err
		}

		config, err := cmd.Flags().GetString("config")
		if err != nil {
			return err
		}

		if config == "" {
			homeDir, _ := os.UserHomeDir()
			config = filepath.Join(homeDir, "gxpc.conf")
		}

		if initConfig {
			configData := OffsetsData{
				Offsets: []Offset{
					{
						OS: "iPhone14,7",
						Builds: []map[string]BuildData{
							{
								"20B110": {PlistCreate: "0xb1c00", CallHandler: "0x11c00"},
							},
						},
					},
					{
						OS: "iPad7,11",
						Builds: []map[string]BuildData{
							{"22B83": {PlistCreate: "0x7dbf4", CallHandler: "0xf98c"}},
						},
					},
				},
			}

			f, err := os.Create(config)
			if err != nil {
				return err
			}
			defer f.Close()

			encoder := json.NewEncoder(f)
			encoder.SetIndent("  ", "    ")

			if err := encoder.Encode(configData); err != nil {
				return err
			}

			logger.Infof("Created new config at %s", config)
			return nil
		}

		list, err := cmd.Flags().GetBool("list")
		if err != nil {
			return err
		}

		id, err := cmd.Flags().GetString("id")
		if err != nil {
			return err
		}

		remote, err := cmd.Flags().GetString("remote")
		if err != nil {
			return err
		}

		pid, err := cmd.Flags().GetInt("pid")
		if err != nil {
			return err
		}

		procName, err := cmd.Flags().GetString("name")
		if err != nil {
			return err
		}

		output, err := cmd.Flags().GetString("output")
		if err != nil {
			return err
		}

		if output != "" {
			if err := logger.SetOutput(output); err != nil {
				return err
			}
		}

		mgr := frida.NewDeviceManager()
		devices, err := mgr.EnumerateDevices()
		if err != nil {
			return err
		}

		if list {
			for _, d := range devices {
				logger.Infof("[%s]\t%s (%s)\n",
					strings.ToUpper(d.DeviceType().String()),
					d.Name(),
					d.ID())
			}
			return nil
		}

		var dev *frida.Device
		var session *frida.Session

		for _, d := range devices {
			if id != "" {
				if d.ID() == id {
					dev = d.(*frida.Device)
					break
				}
			} else if remote != "" {
				rdevice, err := mgr.AddRemoteDevice(remote, nil)
				if err != nil {
					return err
				}
				dev = rdevice.(*frida.Device)
				break
			} else {
				dev = frida.USBDevice()
			}
		}

		if dev == nil {
			return errors.New("could not obtain specified device")
		}
		defer dev.Clean()
		logger.Infof("Using device %s (%s)", dev.Name(), dev.ID())

		procPid := pid

		if pid == -1 && procName != "" {
			processes, err := dev.EnumerateProcesses(frida.ScopeMinimal)
			if err != nil {
				return err
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
			return err
		}

		if procPid == -1 && file == "" {
			return errors.New("missing pid, name or file to spawn")
		}

		spawned := false

		if procPid != -1 {
			session, err = dev.Attach(procPid, nil)
			if err != nil {
				return err
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
				return err
			}
			procPid = spawnedPID
			session, err = dev.Attach(spawnedPID, nil)
			if err != nil {
				return err
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
			return err
		}
		defer script.Clean()

		blacklist, err := cmd.Flags().GetStringSlice("blacklist")
		if err != nil {
			return err
		}

		whitelist, err := cmd.Flags().GetStringSlice("whitelist")
		if err != nil {
			return err
		}

		blacklistp, err := cmd.Flags().GetStringSlice("blacklistp")
		if err != nil {
			return err
		}

		whitelistp, err := cmd.Flags().GetStringSlice("whitelist")
		if err != nil {
			return err
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
					logger.Warnf("SCRIPT: %v", subPayload)
				}

			case frida.MessageTypeLog:
				logger.Infof("SCRIPT: %v", msg.Payload.(string))
			default:
				logger.Errorf("SCRIPT: %v", msg)
			}
		})

		if err := script.Load(); err != nil {
			return err
		}
		logger.Infof("Loaded script to the process")

		if spawned {
			if err := dev.Resume(procPid); err != nil {
				return err
			} else {
				logger.Infof("Resumed process")
			}
		}

		if config == "" {
			homeDir, _ := os.UserHomeDir()
			config = filepath.Join(homeDir, "gxpc.conf")
		}

		var offsets OffsetsData
		f, err := os.Open(config)
		if err != nil {
			return err
		}
		defer f.Close()

		if err := json.NewDecoder(f).Decode(&offsets); err != nil {
			return err
		}

		_ = script.ExportsCall("setup", offsets)

		c := make(chan os.Signal)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)

		select {
		case <-c:
			fmt.Println()
			logger.Infof("Exiting...")
			if err := script.Unload(); err != nil {
				return err
			}
			logger.Infof("Script unloaded")
		case <-detached:
			logger.Infof("Exiting...")
		}
		return nil
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

func setupFlags() {
	rootCmd.Flags().StringP("id", "i", "", "connect to device with ID")
	rootCmd.Flags().StringP("remote", "r", "", "connect to device at IP address")
	rootCmd.Flags().StringP("name", "n", "", "process name")
	rootCmd.Flags().StringP("file", "f", "", "spawn the file")
	rootCmd.Flags().StringP("output", "o", "", "save output to this file")

	rootCmd.Flags().StringP("config", "c", "", "path to gxpc.conf file; default user home directory")
	rootCmd.Flags().BoolP("init", "", false, "create gxpc.conf file with offsets")

	rootCmd.Flags().StringSliceP("whitelist", "w", []string{}, "whitelist connection by name")
	rootCmd.Flags().StringSliceP("blacklist", "b", []string{}, "blacklist connection by name")
	rootCmd.Flags().StringSliceP("whitelistp", "", []string{}, "whitelist connection by PID")
	rootCmd.Flags().StringSliceP("blacklistp", "", []string{}, "blacklist connection by PID")

	rootCmd.Flags().BoolP("list", "l", false, "list available devices")
	//rootCmd.Flags().BoolP("decode", "d", true, "try to decode(bplist00 or bplist15), otherwise print base64 of bytes")
	//rootCmd.Flags().BoolP("hex", "x", false, "print hexdump of raw data")

	rootCmd.Flags().IntP("pid", "p", -1, "PID of wanted process")
}

func main() {
	setupFlags()
	logger = NewLogger()
	defer logger.Close()

	if err := rootCmd.Execute(); err != nil {
		logger.Errorf("Error ocurred: %v", err)
	}
}
