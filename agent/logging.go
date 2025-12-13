//go:build windows
// +build windows

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/kardianos/service"
)

var (
	agentLogFile   *os.File
	agentLogFileMu sync.Mutex
)

func openDefaultAgentLogFile(primary service.Logger) (*os.File, string) {
	// Default requested location:
	primaryPath := `C:\winaflpet-agent.log`

	f, err := os.OpenFile(primaryPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err == nil {
		return f, primaryPath
	}

	// Fallback to %TEMP% if C:\ is not writable.
	fallbackPath := filepath.Join(os.TempDir(), "winaflpet-agent.log")
	ff, err2 := os.OpenFile(fallbackPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err2 == nil && primary != nil {
		_ = primary.Warningf("Failed to open %s for logging (%v). Falling back to %s", primaryPath, err, fallbackPath)
	}
	return ff, fallbackPath
}

type teeServiceLogger struct {
	primary service.Logger
	filelog  *log.Logger
}

func (l *teeServiceLogger) Error(v ...interface{}) error {
	var err error
	if l.primary != nil {
		err = l.primary.Error(v...)
	}
	if l.filelog != nil {
		l.filelog.Print("ERROR ", fmt.Sprint(v...))
	}
	return err
}

func (l *teeServiceLogger) Warning(v ...interface{}) error {
	var err error
	if l.primary != nil {
		err = l.primary.Warning(v...)
	}
	if l.filelog != nil {
		l.filelog.Print("WARN  ", fmt.Sprint(v...))
	}
	return err
}

func (l *teeServiceLogger) Info(v ...interface{}) error {
	var err error
	if l.primary != nil {
		err = l.primary.Info(v...)
	}
	if l.filelog != nil {
		l.filelog.Print("INFO  ", fmt.Sprint(v...))
	}
	return err
}

func (l *teeServiceLogger) Errorf(format string, a ...interface{}) error {
	var err error
	if l.primary != nil {
		err = l.primary.Errorf(format, a...)
	}
	if l.filelog != nil {
		l.filelog.Printf("ERROR "+format, a...)
	}
	return err
}

func (l *teeServiceLogger) Warningf(format string, a ...interface{}) error {
	var err error
	if l.primary != nil {
		err = l.primary.Warningf(format, a...)
	}
	if l.filelog != nil {
		l.filelog.Printf("WARN  "+format, a...)
	}
	return err
}

func (l *teeServiceLogger) Infof(format string, a ...interface{}) error {
	var err error
	if l.primary != nil {
		err = l.primary.Infof(format, a...)
	}
	if l.filelog != nil {
		l.filelog.Printf("INFO  "+format, a...)
	}
	return err
}

func wrapLoggerWithFile(primary service.Logger) service.Logger {
	agentLogFileMu.Lock()
	defer agentLogFileMu.Unlock()

	// Only open once.
	if agentLogFile == nil {
		f, path := openDefaultAgentLogFile(primary)
		agentLogFile = f
		if primary != nil && f != nil {
			_ = primary.Infof("Agent file logging enabled: %s", path)
		}
	}

	var ll *log.Logger
	if agentLogFile != nil {
		ll = log.New(agentLogFile, "", log.Ldate|log.Ltime|log.Lmicroseconds)
	}

	return &teeServiceLogger{
		primary: primary,
		filelog:  ll,
	}
}

func closeAgentLogFile() {
	agentLogFileMu.Lock()
	defer agentLogFileMu.Unlock()
	if agentLogFile != nil {
		_ = agentLogFile.Close()
		agentLogFile = nil
	}
}


