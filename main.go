package main

import (
	_ "embed"
	"fmt"
	"github.com/frida/frida-go/frida"
	"github.com/spf13/cobra"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

//go:embed script.js
var scContent string

var rootCmd = &cobra.Command{
	Use:   "gxpc",
	Short: "XPC analyzer",
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

		if pid == -1 {
			logger.Errorf("Cannot attach to process with PID => -1")
			return
		}

		session, err := dev.Attach(pid, nil)
		if err != nil {
			logger.Errorf("Error attaching: %v", err)
			return
		}
		defer session.Clean()
		logger.Infof("Attached to the process with PID => %d", pid)

		detached := make(chan struct{})

		session.On("detached", func(reason frida.SessionDetachReason) {
			logger.Errorf("Session detached: %s", reason.String())
			detached <- struct{}{}
		})

		script, err := session.CreateScript(scContent)
		if err != nil {
			logger.Errorf("Error creating script: %v", err)
			return
		}
		defer script.Clean()

		script.On("message", func(message string) {
			msg, _ := frida.ScriptMessageToMessage(message)
			if msg.Type == frida.MessageTypeSend {
				logger.Scriptf("%v", msg.Payload)
			}
		})

		if err := script.Load(); err != nil {
			logger.Errorf("Error loading script: %v", err)
			return
		}
		logger.Infof("Loaded script to the process")

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
			if err := script.Unload(); err != nil {
				logger.Errorf("Error unloading script: %v", err)
				return
			}
			logger.Infof("Script unloaded")
		}
	},
}

func main() {
	rootCmd.Flags().BoolP("list", "l", false, "list available devices")
	rootCmd.Flags().StringP("id", "i", "", "connect to device with ID")
	rootCmd.Flags().StringP("remote", "r", "", "connect to device at IP address")
	rootCmd.Flags().IntP("pid", "p", -1, "PID of wanted process")

	rootCmd.Execute()
}
