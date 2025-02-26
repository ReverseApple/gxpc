package main

import (
	"encoding/json"
	"io"
	"os"
)

type BuildData struct {
	PlistCreate string `json:"PlistCreate"`
	CallHandler string `json:"CallHandler"`
}

type Offset struct {
	OS     string                 `json:"os"`
	Builds []map[string]BuildData `json:"builds"`
}

type OffsetsData struct {
	Offsets []Offset `json:"offsets"`
}

type NewOffset struct {
	Machine     string `json:"machine"`
	Version     string `json:"version"`
	CallEvent   string `json:"callEvent"`
	PlistCreate string `json:"plistCreate"`
}

func updateConfig(configPath string, off *NewOffset) error {
	// there is no config file yet created, create one and append data to it
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		f, err := os.Create(configPath)
		if err != nil {
			return err
		}
		defer f.Close()
		configData := OffsetsData{
			Offsets: []Offset{
				{
					OS: off.Machine,
					Builds: []map[string]BuildData{
						{
							off.Version: {
								PlistCreate: off.PlistCreate,
								CallHandler: off.CallEvent,
							},
						},
					},
				},
			},
		}
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		return enc.Encode(configData)
	} else {
		var configData OffsetsData
		f, err := os.OpenFile(configPath, os.O_RDWR, 644)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := json.NewDecoder(f).Decode(&configData); err != nil {
			return err
		}

		// TODO: we need to implement a check for different builds for the same platform
		configData.Offsets = append(configData.Offsets, Offset{
			OS: off.Machine,
			Builds: []map[string]BuildData{
				{
					off.Version: {
						PlistCreate: off.PlistCreate,
						CallHandler: off.CallEvent,
					},
				},
			},
		})

		f.Truncate(0)
		f.Seek(0, io.SeekStart)
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		return enc.Encode(configData)
	}
}
