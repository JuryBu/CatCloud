//go:build android && cmfa

package main

import (
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultMemoryLimitBytes int64 = 32 << 20
	minMemoryLimitBytes     int64 = 16 << 20
	maxMemoryLimitBytes     int64 = 128 << 20

	defaultGCPercent = 25
	minGCPercent     = 10
	maxGCPercent     = 200
)

var (
	memConfigured atomic.Bool
	gcInFlight    atomic.Bool

	freeTimerMu sync.Mutex
	freeTimer   *time.Timer
)

func applyDefaultMemoryPolicy() {
	if memConfigured.CompareAndSwap(false, true) {
		debug.SetGCPercent(defaultGCPercent)
		debug.SetMemoryLimit(defaultMemoryLimitBytes)
	}
}

func setMemoryLimit(limitBytes int64, gcPercent int) {
	memConfigured.Store(true)

	if limitBytes > 0 {
		if limitBytes < minMemoryLimitBytes {
			limitBytes = minMemoryLimitBytes
		} else if limitBytes > maxMemoryLimitBytes {
			limitBytes = maxMemoryLimitBytes
		}
		debug.SetMemoryLimit(limitBytes)
	}

	if gcPercent > 0 {
		if gcPercent < minGCPercent {
			gcPercent = minGCPercent
		} else if gcPercent > maxGCPercent {
			gcPercent = maxGCPercent
		}
		debug.SetGCPercent(gcPercent)
	}
}

func scheduleDelayedFreeOSMemory(delay time.Duration) {
	freeTimerMu.Lock()
	defer freeTimerMu.Unlock()

	if freeTimer != nil {
		freeTimer.Stop()
	}
	freeTimer = time.AfterFunc(delay, func() {
		debug.FreeOSMemory()
	})
}

func triggerForceGcAsync() {
	if !gcInFlight.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer gcInFlight.Store(false)
		runtime.GC()
		debug.FreeOSMemory()
	}()
}
