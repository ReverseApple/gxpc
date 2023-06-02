package main

import (
	"github.com/fatih/color"
	"log"
	"os"
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
}

func NewLogger() *Logger {
	return &Logger{
		infoLogger:   log.New(os.Stdout, infoColor.Sprintf("%s  ", "⬥"), 0),
		warnLogger:   log.New(os.Stdout, warnColor.Sprintf("%s  ", "⬥"), 0),
		errorLogger:  log.New(os.Stderr, errorColor.Sprintf("%s  ", "⬥"), 0),
		fatalLogger:  log.New(os.Stderr, fatalColor.Sprintf("%s  ", "⬥"), 0),
		scriptLogger: log.New(os.Stdout, scriptColor.Sprintf("%s  ", "⬥"), 0),
	}
}

func (l *Logger) Infof(format string, args ...any) {
	l.infoLogger.Printf(format, args...)
}

func (l *Logger) Warnf(format string, args ...any) {
	l.warnLogger.Printf(format, args...)
}

func (l *Logger) Errorf(format string, args ...any) {
	l.errorLogger.Printf(format, args...)
}

func (l *Logger) Fatalf(format string, args ...any) {
	l.fatalLogger.Printf(format, args...)
	os.Exit(1)
}

func (l *Logger) Scriptf(format string, args ...any) {
	l.scriptLogger.Printf(format, args...)
}
