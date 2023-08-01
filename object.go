package main

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

func PrintData(value any, decode, printHex bool, whitelist, blacklist []*regexp.Regexp, logger *Logger) {
	val := reflect.ValueOf(value)

	data := make(map[string]any)

	if val.Kind() == reflect.Map {
		for _, elem := range val.MapKeys() {
			v := val.MapIndex(elem)
			data[elem.Interface().(string)] = v.Interface()
		}
	}
	name := data["connName"].(string)

	if len(whitelist) > 0 {
		if !connInList(name, whitelist) {
			return
		}
	} else {
		if connInList(name, blacklist) {
			return
		}
	}

	var message string
	fnName := fmt.Sprintf("Name: %s\n", data["name"])
	connName := fmt.Sprintf("Connection Name: %s\n", data["connName"])
	printData(reflect.ValueOf(data["dictionary"]), "", "", &message)
	total := len(fnName) + len(connName) + len(message) + 100

	builder := strings.Builder{}
	builder.Grow(total)

	builder.WriteString(fnName)
	builder.WriteString(connName)
	builder.WriteString("Data:\n")
	builder.WriteString(message)
	builder.WriteString(fmt.Sprintf("\n%s\n", strings.Repeat("=", 80)))

	logger.Scriptf("Name: %s", data["name"])
	logger.Scriptf("Connection Name: %s", data["connName"])
	pid, ok := data["pid"].(float64)
	if ok {
		logger.Scriptf("PID: %d", int(pid))
	}
	logger.Scriptf("Data:")
	logger.Scriptf("%s", message)
	fmt.Println(strings.Repeat("=", 80))

	logger.writeToFileScript(builder.String())
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

func connInList(connName string, list []*regexp.Regexp) bool {
	for _, b := range list {
		if match := b.MatchString(connName); match {
			return true
		}
	}
	return false
}
