package main

import (
	"fmt"
	"github.com/fatih/color"
	"log"
	"os"
	"strings"
	"time"
)

var (
	infoColor   = color.New(color.FgGreen)
	warnColor   = color.New(color.FgYellow)
	errorColor  = color.New(color.FgRed)
	fatalColor  = color.New(color.FgHiRed)
	scriptColor = color.New(color.FgMagenta)
)

type Logger struct {
	infoLogger   *log.Logger
	warnLogger   *log.Logger
	errorLogger  *log.Logger
	fatalLogger  *log.Logger
	scriptLogger *log.Logger
	f            *os.File
}

func NewLogger() *Logger {
	return &Logger{
		infoLogger:   log.New(os.Stdout, infoColor.Sprintf("%s  ", "⚡"), 0),
		warnLogger:   log.New(os.Stdout, warnColor.Sprintf("%s  ", "⚠"), 0),
		errorLogger:  log.New(os.Stderr, errorColor.Sprintf("%s  ", "❗️"), 0),
		fatalLogger:  log.New(os.Stderr, fatalColor.Sprintf("%s  ", "⛔️"), 0),
		scriptLogger: log.New(os.Stdout, scriptColor.Sprintf("%s  ", "✅"), 0),
	}
}

func (l *Logger) SetOutput(output string) error {
	f, err := os.OpenFile(output, os.O_RDWR|os.O_CREATE|os.O_APPEND, os.ModePerm)
	if err != nil {
		return err
	}
	l.f = f
	return nil
}

func (l *Logger) Close() error {
	if l.f != nil {
		return l.f.Close()
	}
	return nil
}

func (l *Logger) Infof(format string, args ...any) {
	l.infoLogger.Printf(format, args...)
	l.writeToFile("INFO", format, args...)
}

func (l *Logger) Warnf(format string, args ...any) {
	l.warnLogger.Printf(format, args...)
	l.writeToFile("WARN", format, args...)
}

func (l *Logger) Errorf(format string, args ...any) {
	l.errorLogger.Printf(format, args...)
	l.writeToFile("ERRO", format, args...)
}

func (l *Logger) Fatalf(format string, args ...any) {
	l.fatalLogger.Printf(format, args...)
	l.writeToFile("FATA", format, args...)
	os.Exit(1)
}

func (l *Logger) Scriptf(format string, args ...any) {
	l.scriptLogger.Printf(format, args...)
}

func (l *Logger) writeToFile(level, format string, args ...any) {
	if l.f != nil {
		t := time.Now().Format(time.RFC3339)
		msg := fmt.Sprintf("%s\n%s: %s\n%s\n",
			t, level, fmt.Sprintf(format, args...), strings.Repeat("=", 80))
		l.f.WriteString(msg)
	}
}

func (l *Logger) writeToFileScript(body string) {
	if l.f != nil {
		t := time.Now().Format(time.RFC3339)
		l.f.WriteString(t + "\nSCRI: " + body)
	}
}
