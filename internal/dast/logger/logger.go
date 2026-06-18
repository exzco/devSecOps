package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	logMu        sync.Mutex
	printConsole = true
	logFilePath  = filepath.Join("log", "dast_log.json")
)

func SetConsolePrint(enable bool) {
	logMu.Lock()
	defer logMu.Unlock()
	printConsole = enable
}

type LogEntry struct {
	Time    string `json:"time"`
	Message string `json:"message"`
}

func Printf(format string, v ...interface{}) {
	logMu.Lock()
	defer logMu.Unlock()

	msg := fmt.Sprintf(format, v...)

	if printConsole {
		fmt.Print(msg)
	}

	_ = os.MkdirAll("log", 0755)

	entry := LogEntry{
		Time:    time.Now().Format(time.RFC3339),
		Message: strings.TrimRight(msg, "\n"),
	}

	data, err := json.Marshal(entry)
	if err == nil {
		f, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			_, _ = f.Write(append(data, '\n'))
			_ = f.Close()
		}
	}
}

func Println(v ...interface{}) {
	msg := fmt.Sprintln(v...)
	Printf("%s", msg)
}
