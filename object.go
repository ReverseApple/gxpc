package main

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

type ctr struct {
	c int
	l *sync.Mutex
}

var c = &ctr{l: &sync.Mutex{}}

func PrintData(value any, decode, printHex bool,
	whitelist, blacklist, whitelistp, blacklistp []*regexp.Regexp,
	logger *Logger) {
	msg := 0

	val := reflect.ValueOf(value)

	data := make(map[string]any)

	if val.Kind() == reflect.Map {
		for _, elem := range val.MapKeys() {
			v := val.MapIndex(elem)
			data[elem.Interface().(string)] = v.Interface()
		}
	}
	name := data["connName"].(string)

	var pid float64
	if _, ok := data["pid"].(float64); ok {
		pid = data["pid"].(float64)
	}

	if len(whitelist) > 0 || len(blacklist) > 0 {
		if len(whitelist) > 0 && !connInList(name, whitelist) {
			return
		} else {
			if connInList(name, blacklist) {
				return
			}
		}
	} else {
		if pid > 0 {
			if len(whitelistp) > 0 && !pidInList(pid, whitelistp) {
				return
			} else {
				if pidInList(pid, blacklistp) {
					return
				}
			}
		}
	}

	c.l.Lock()
	msg = c.c
	c.c++
	c.l.Unlock()

	var message string
	fnName := fmt.Sprintf("%d) Name: %s\n", msg, data["name"])
	connName := fmt.Sprintf("Connection Name: %s\n", data["connName"])
	process := ""
	pid, pidOK := data["pid"].(float64)
	if pidOK {
		process = fmt.Sprintf("Process: %s[%d]\n", data["procName"], int(pid))
	}
	if _, ok := data["dictionary"]; ok {
		printData(reflect.ValueOf(data["dictionary"]), "", "", &message)
	}
	total := len(fnName) + len(connName) + len(process) + len(message) + 100

	builder := strings.Builder{}
	builder.Grow(total)

	builder.WriteString(fnName)
	builder.WriteString(connName)
	builder.WriteString(process)
	builder.WriteString("Data:\n")
	builder.WriteString(message)
	builder.WriteString(fmt.Sprintf("\n%s\n", strings.Repeat("=", 80)))

	logger.Scriptf("%d) Name: %s", msg, data["name"])
	logger.Scriptf("Connection Name: %s", data["connName"])
	if pidOK {
		logger.Scriptf("Process: %s[%d]", data["procName"], int(pid))
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

func pidInList(pid float64, list []*regexp.Regexp) bool {
	ps := fmt.Sprintf("%f", pid)
	for _, b := range list {
		if match := b.MatchString(ps); match {
			return true
		}
	}
	return false
}
