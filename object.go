package main

import (
	"fmt"
	"reflect"
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
		logger.Scriptf("Dictionary:")
		content, ok := data["dictionary"].(map[string]any)
		if ok {
			for k, v := range content {
				var message string
				printData(reflect.ValueOf(v), k, "\t", &message)
				logger.Scriptf("%s", message)
				//logger.Scriptf("\t%v => %v", k, v)
			}
		}
		fmt.Printf("==========================================================\n\n")
	}
}

func printData(v reflect.Value, key, indent string, message *string) {
	if v.Kind() == reflect.Interface || v.Kind() == reflect.Pointer {
		v = v.Elem()
	}

	switch v.Kind() {
	case reflect.Map:
		*message += fmt.Sprintf("%s%s => \n", indent, key)
		for _, k := range v.MapKeys() {
			printData(v.MapIndex(k), k.Interface().(string), indent+"\t", message)
		}
	case reflect.Array, reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			printData(v.Index(i), key, indent+"\t", message)
		}
	default:
		*message += fmt.Sprintf("%s%s => %v\n", indent, key, v.Interface())
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
