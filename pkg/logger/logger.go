package logger

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	mu           sync.Mutex
	logDir       = "./result/log"
	logFile      *os.File
	printConsole = true
)

// Configure sets optional log directory and console output flag.
func Configure(dir string, console bool) {
	mu.Lock()
	defer mu.Unlock()

	printConsole = console
	if dir == "" {
		dir = "./result/log"
	}
	logDir = dir
	_ = os.MkdirAll(logDir, 0755)
	filePath := fmt.Sprintf("%s/app.log", logDir)
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		if logFile != nil {
			_ = logFile.Close()
		}
		logFile = f
	}
}

// Logf prints a log entry in standard format: 2026-07-26 00:29 [module] [xxxx日志信息]
func Logf(module string, format string, v ...interface{}) {
	mu.Lock()
	defer mu.Unlock()

	nowStr := time.Now().Format("2006-01-02 15:04:05")
	msg := fmt.Sprintf(format, v...)
	msg = strings.TrimRight(msg, "\r\n")

	line := fmt.Sprintf("%s [%s] [%s]\n", nowStr, module, msg)

	if printConsole {
		fmt.Print(line)
	}

	if logFile != nil {
		_, _ = logFile.WriteString(line)
	}
}

// Logln prints a log entry using Sprintln formatting
func Logln(module string, v ...interface{}) {
	msg := fmt.Sprintln(v...)
	Logf(module, "%s", msg)
}

// SAST logs SAST module messages (e.g., SAST-Runner, SAST-Worker, SAST-CodeQL)
func SAST(submodule string, format string, v ...interface{}) {
	module := "SAST"
	if submodule != "" {
		module = "SAST-" + submodule
	}
	Logf(module, format, v...)
}

// DAST logs DAST module messages (e.g., DAST-Engine, DAST-Worker, DAST-Queue)
func DAST(submodule string, format string, v ...interface{}) {
	module := "DAST"
	if submodule != "" {
		module = "DAST-" + submodule
	}
	Logf(module, format, v...)
}

// SCA logs SCA module messages (e.g., SCA-Scanner, SCA-Parser)
func SCA(submodule string, format string, v ...interface{}) {
	module := "SCA"
	if submodule != "" {
		module = "SCA-" + submodule
	}
	Logf(module, format, v...)
}

// APP logs general application lifecycle messages (e.g., APP-Bootstrap, APP-Server)
func APP(submodule string, format string, v ...interface{}) {
	module := "APP"
	if submodule != "" {
		module = "APP-" + submodule
	}
	Logf(module, format, v...)
}

// Preflight logs preflight check messages
func Preflight(submodule string, format string, v ...interface{}) {
	module := "PREFLIGHT"
	if submodule != "" {
		module = "PREFLIGHT-" + submodule
	}
	Logf(module, format, v...)
}
