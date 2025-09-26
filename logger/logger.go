package logger

import (
	"log"
	"sync"
)

var (
	debugEnabled bool
	mu           sync.RWMutex
)

func SetDebug(enabled bool) {
	mu.Lock()
	defer mu.Unlock()
	debugEnabled = enabled
}

func Debug(format string, args ...interface{}) {
	mu.RLock()
	enabled := debugEnabled
	mu.RUnlock()

	if enabled {
		log.Printf("debug: "+format, args...)
	}
}