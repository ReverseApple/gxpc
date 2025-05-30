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

const (
	agentFilename = "_agent.js"
)

//go:embed script.ts
var scriptContent []byte

//go:embed package.json
var packageJSON []byte

//go:embed package-lock.json
var packageLockJSON []byte

var tempFiles = map[string][]byte{
	"script.ts":         scriptContent,
	"package.json":      packageJSON,
	"package-lock.json": packageLockJSON,
}

var Version string

var logger *Logger = nil

var rootCmd = &cobra.Command{
	Use:           "gxpc [spawn_args]",
	Short:         "XPC sniffer",
	Version:       Version,
	SilenceErrors: true,
	SilenceUsage:  true,
	RunE: func(cmd *cobra.Command, args []string) error {
		config, err := cmd.Flags().GetString("config")
		if err != nil {
			return err
		}

		if config == "" {
			home, _ := os.UserHomeDir()
			config = filepath.Join(home, "gxpc.conf")
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

		// Create temp files
		tempDir := filepath.Join(os.TempDir(), "gxpc")

		os.MkdirAll(tempDir, os.ModePerm)

		if _, err = os.Stat(filepath.Join(tempDir, "script.ts")); os.IsNotExist(err) {
			for fl, data := range tempFiles {
				os.WriteFile(filepath.Join(tempDir, fl), data, os.ModePerm)
			}
		}

		if _, err = os.Stat(filepath.Join(tempDir, "node_modules")); os.IsNotExist(err) {
			// Install modules
			pwd, _ := os.Getwd()
			os.Chdir(tempDir)
			command := exec.Command("npm", "install")
			if err := command.Run(); err != nil {
				logger.Errorf("Error installing modules: %v", err)
			}
			os.Chdir(pwd)
		}

		agentPath := filepath.Join(tempDir, agentFilename)
		var scriptBody string

		// check if we have script.ts already compiled
		if _, err = os.Stat(agentPath); os.IsNotExist(err) {
			comp := frida.NewCompiler()

			comp.On("finished", func() {
				logger.Infof("Done compiling script")
			})

			comp.On("diagnostics", func(diag string) {
				logger.Errorf("compilation error: %v", diag)
			})

			buildOptions := frida.NewCompilerOptions()
			buildOptions.SetProjectRoot(tempDir)
			buildOptions.SetJSCompression(frida.JSCompressionTerser)
			buildOptions.SetSourceMaps(frida.SourceMapsOmitted)

			bundle, err := comp.Build("script.ts", buildOptions)
			if err != nil {
				return fmt.Errorf("error compiling script: %v", err)
			}

			if err := os.WriteFile(agentPath, []byte(bundle), os.ModePerm); err != nil {
				return fmt.Errorf("error saving agent script: %v", err)
			}

			scriptBody = bundle
		} else {
			data, err := os.ReadFile(agentPath)
			if err != nil {
				return fmt.Errorf("error reading agent script: %v", err)
			}
			scriptBody = string(data)
		}

		script, err := session.CreateScript(scriptBody)
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

		var offsets *OffsetsData = nil

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

				case "newOffset":
					var newOffset NewOffset
					for k, v := range payload {
						val := v.(string)
						switch k {
						case "callEvent":
							newOffset.CallEvent = val
						case "plistCreate":
							newOffset.PlistCreate = val
						case "machine":
							newOffset.Machine = val
						case "version":
							newOffset.Version = val
						}
					}
					updateConfig(config, &newOffset)
					logger.Infof("Saved offset for %s (%s)", newOffset.Machine, newOffset.Version)

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

		if _, err := os.Stat(config); os.IsNotExist(err) {
			_ = script.ExportsCall("setup", nil)
		} else {
			f, err := os.Open(config)
			if err != nil {
				return err
			}
			defer f.Close()
			offsets = &OffsetsData{}
			if err := json.NewDecoder(f).Decode(offsets); err != nil {
				return err
			}
			_ = script.ExportsCall("setup", offsets)
		}

		logger.Infof("Finished setup")

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
