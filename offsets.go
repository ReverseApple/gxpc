package main

type BuildData struct {
	PlistCreate string `json:"PlistCreate"`
	CallHandler string `json:"CallHandler"`
}

type Offset struct {
	OS     string               `json:"os"`
	Builds map[string]BuildData `json:"builds"`
}

type OffsetsData struct {
	Offsets []Offset `json:"offsets"`
}
