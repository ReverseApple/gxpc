package main

import (
	"fmt"
	"reflect"
	"strconv"
)

func PrintData(value any, decode, printHex bool, blacklist []string, logger *Logger) {
	val := reflect.ValueOf(value)

	data := make(map[string]any)

	if val.Kind() == reflect.Map {
		for _, elem := range val.MapKeys() {
			v := val.MapIndex(elem)
			data[elem.Interface().(string)] = v.Interface()
		}
	}
	name := data["connName"].(string)
	if !connectionNameInBlacklist(name, blacklist) {
		logger.Scriptf("Name: %s", data["name"])
		logger.Scriptf("Connection Name: %s", data["connName"])
		logger.Scriptf("Data:")
		var message string
		printData(reflect.ValueOf(data["dictionary"]), "", "", &message)
		logger.Scriptf("%s", message)
		fmt.Printf("==========================================================\n\n")
	}
}

func printData(v reflect.Value, key, indent string, message *string) {
	if v.Kind() == reflect.Interface || v.Kind() == reflect.Pointer {
		v = v.Elem()
	}

	switch v.Kind() {
	case reflect.Map:
		if key != "" {
			*message += fmt.Sprintf("%s%s => \n", indent, key)
		} else {
			*message += fmt.Sprintf("")
		}
		for _, k := range v.MapKeys() {
			printData(v.MapIndex(k), k.Interface().(string), indent+"\t", message)
		}
	case reflect.Array, reflect.Slice:
		*message += fmt.Sprintf("%s%s => [\n", indent, key)
		*message += indent + "[\n"
		for i := 0; i < v.Len(); i++ {
			keyNum := strconv.Itoa(i)
			printData(v.Index(i), keyNum, indent+"\t", message)
		}
		*message += indent + "]\n"
	default:
		if key != "" {
			*message += fmt.Sprintf("%s%s => %v\n", indent, key, v.Interface())
		} else {
			*message += fmt.Sprintf("%s => %v\n", indent, v.Interface())
		}
	}
}

func connectionNameInBlacklist(connName string, blacklist []string) bool {
	for _, b := range blacklist {
		if connName == b {
			return true
		}
	}
	return false
}
