//go:build android && cmfa

package main

/*
#include <stdlib.h>
#include "catcloud_jni.h"
*/
import "C"

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/iface"
	"github.com/metacubex/mihomo/component/process"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/config"
	constant "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/hub/route"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

type socketProtectFunc func(fd int) bool

var (
	bridgeMu sync.Mutex

	// Permanently referenced by dialer.DefaultSocketHook; swapped atomically so
	// dialer.DefaultSocketHook is never mutated to nil at runtime (CMFA #852).
	activeProtectFn atomic.Pointer[socketProtectFunc]

	configPrepared atomic.Bool

	controllerStarted    bool
	lastControllerAddr   string
	lastControllerSecret string
)

func init() {
	dialer.DefaultSocketHook = catcloudSocketHook
	route.SetEmbedMode(true)
}

func catcloudSocketHook(network, address string, conn syscall.RawConn) error {
	fnPtr := activeProtectFn.Load()
	if fnPtr == nil || *fnPtr == nil {
		return nil
	}
	protect := *fnPtr
	var protectErr error
	ctrlErr := conn.Control(func(fd uintptr) {
		if !protect(int(fd)) {
			protectErr = fmt.Errorf("VpnService.protect(%d) rejected for %s %s", fd, network, address)
		}
	})
	if ctrlErr != nil {
		return ctrlErr
	}
	return protectErr
}

func isConfigPrepared() bool {
	return configPrepared.Load()
}

func normalizeLoopbackControllerAddr(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("controllerAddr is empty")
	}
	host, portStr, err := net.SplitHostPort(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid controllerAddr %q: %w", trimmed, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return "", fmt.Errorf("invalid controller port %q", portStr)
	}
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "127.0.0.1", "localhost":
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), nil
	default:
		return "", fmt.Errorf("controllerAddr must bind loopback 127.0.0.1, got %q", host)
	}
}

func waitLoopbackListening(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		conn, err := net.DialTimeout("tcp", addr, 40*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("controller failed to listen on %s: %w", addr, err)
		}
		time.Sleep(15 * time.Millisecond)
	}
}

func waitLoopbackClosed(addr string, timeout time.Duration) {
	if addr == "" {
		return
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 25*time.Millisecond)
		if err != nil {
			return
		}
		_ = conn.Close()
		time.Sleep(10 * time.Millisecond)
	}
}

func hardenAndroidConfig(cfg *config.Config, controllerAddr, controllerSecret string) {
	// Never let executor.ApplyConfig spawn its own TUN listener; Android VpnService
	// owns the detached TUN fd and hands it exclusively to nativeAttachTun.
	cfg.General.Tun.Enable = false
	cfg.General.GeoAutoUpdate = false
	cfg.General.FindProcessMode = process.FindProcessOff

	if cfg.IPTables != nil {
		cfg.IPTables.Enable = false
	}
	if cfg.Controller != nil {
		if controllerAddr != "" {
			cfg.Controller.ExternalController = controllerAddr
			cfg.Controller.Secret = controllerSecret
		}
		cfg.Controller.ExternalControllerTLS = ""
		cfg.Controller.ExternalControllerUnix = ""
		cfg.Controller.ExternalControllerPipe = ""
		cfg.Controller.ExternalUI = ""
		cfg.Controller.ExternalUIURL = ""
		cfg.Controller.ExternalDohServer = ""
	}
}

func closeAllTrackedConnections() {
	if statistic.DefaultManager == nil {
		return
	}
	statistic.DefaultManager.Range(func(c statistic.Tracker) bool {
		_ = c.Close()
		return true
	})
}

func stopControllerLocked() {
	if !controllerStarted {
		return
	}
	prevAddr := lastControllerAddr
	controllerStarted = false
	lastControllerAddr = ""
	lastControllerSecret = ""
	route.ReCreateServer(&route.Config{})
	waitLoopbackClosed(prevAddr, 200*time.Millisecond)
}

func parseSystemDNSCSV(dnsCsv string) []string {
	parts := strings.FieldsFunc(dnsCsv, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
	})
	seen := make(map[string]struct{}, len(parts))
	out := make([]string, 0, len(parts))
	for _, raw := range parts {
		token := strings.TrimSpace(raw)
		if token == "" {
			continue
		}
		var normalized string
		if host, port, err := net.SplitHostPort(token); err == nil && host != "" && port != "" {
			if ip, ipErr := netip.ParseAddr(strings.Trim(host, "[]")); ipErr == nil {
				unmapped := ip.Unmap()
				if unmapped.String() == "172.19.0.1" || unmapped.String() == "172.19.0.2" {
					continue
				}
				normalized = net.JoinHostPort(unmapped.String(), port)
			} else {
				normalized = net.JoinHostPort(host, port)
			}
		} else {
			bare := strings.Trim(token, "[]")
			ip, ipErr := netip.ParseAddr(bare)
			if ipErr != nil {
				continue
			}
			unmapped := ip.Unmap()
			if unmapped.String() == "172.19.0.1" || unmapped.String() == "172.19.0.2" {
				continue
			}
			// dns/client.go newClient expects host:port for net.SplitHostPort.
			normalized = net.JoinHostPort(unmapped.String(), "53")
		}
		if _, dup := seen[normalized]; dup {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}

//export catcloud_go_init
func catcloud_go_init(homeDir *C.char) *C.char {
	bridgeMu.Lock()
	defer bridgeMu.Unlock()

	dir := strings.TrimSpace(C.GoString(homeDir))
	if dir == "" {
		return C.CString("homeDir is empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return C.CString(fmt.Sprintf("create homeDir failed: %v", err))
	}

	constant.SetHomeDir(dir)
	constant.SetConfig(filepath.Join(dir, "runtime_config.yaml"))
	applyDefaultMemoryPolicy()

	var protect socketProtectFunc = func(fd int) bool {
		return C.catcloud_protect_socket(C.int(fd)) != 0
	}
	activeProtectFn.Store(&protect)
	return nil
}

//export catcloud_go_set_memory_limit
func catcloud_go_set_memory_limit(limitBytes C.longlong, gcPercent C.int) {
	setMemoryLimit(int64(limitBytes), int(gcPercent))
}

//export catcloud_go_prepare_config
func catcloud_go_prepare_config(configYaml *C.char, controllerAddr *C.char, controllerSecret *C.char) *C.char {
	bridgeMu.Lock()
	defer bridgeMu.Unlock()

	yamlText := C.GoString(configYaml)
	if strings.TrimSpace(yamlText) == "" {
		return C.CString("configYaml is empty")
	}

	normalizedAddr, err := normalizeLoopbackControllerAddr(C.GoString(controllerAddr))
	if err != nil {
		return C.CString(err.Error())
	}
	secret := C.GoString(controllerSecret)

	cfg, err := executor.ParseWithBytes([]byte(yamlText))
	if err != nil {
		return C.CString(fmt.Sprintf("parse config failed: %v", err))
	}
	hardenAndroidConfig(cfg, normalizedAddr, secret)

	executor.ApplyConfig(cfg, true)

	needRestartController := !controllerStarted || lastControllerAddr != normalizedAddr || lastControllerSecret != secret
	if needRestartController {
		samePortNewSecret := controllerStarted && lastControllerAddr == normalizedAddr
		routeCfg := &route.Config{
			Addr:    normalizedAddr,
			Secret:  secret,
			IsDebug: cfg.General.LogLevel == log.DEBUG,
		}
		if cfg.Controller != nil {
			routeCfg.Cors = route.Cors{
				AllowOrigins:        cfg.Controller.Cors.AllowOrigins,
				AllowPrivateNetwork: cfg.Controller.Cors.AllowPrivateNetwork,
			}
		}
		route.ReCreateServer(routeCfg)
		if samePortNewSecret {
			// Give async start() a brief window to close old httpServer before probing.
			time.Sleep(25 * time.Millisecond)
		}
		if err := waitLoopbackListening(normalizedAddr, 800*time.Millisecond); err != nil {
			controllerStarted = false
			lastControllerAddr = ""
			lastControllerSecret = ""
			return C.CString(err.Error())
		}
		controllerStarted = true
		lastControllerAddr = normalizedAddr
		lastControllerSecret = secret
	}

	configPrepared.Store(true)
	scheduleDelayedFreeOSMemory(2 * time.Second)
	return nil
}

//export catcloud_go_attach_tun
func catcloud_go_attach_tun(tunFd C.int, mtu C.int) *C.char {
	if err := attachTun(int(tunFd), int(mtu)); err != nil {
		return C.CString(err.Error())
	}
	return nil
}

//export catcloud_go_reload_config
func catcloud_go_reload_config(configYaml *C.char) *C.char {
	bridgeMu.Lock()
	defer bridgeMu.Unlock()

	yamlText := C.GoString(configYaml)
	if strings.TrimSpace(yamlText) == "" {
		return C.CString("configYaml is empty")
	}

	cfg, err := executor.ParseWithBytes([]byte(yamlText))
	if err != nil {
		return C.CString(fmt.Sprintf("parse reload config failed: %v", err))
	}
	hardenAndroidConfig(cfg, "", "")

	executor.ApplyConfig(cfg, true)
	configPrepared.Store(true)
	scheduleDelayedFreeOSMemory(2 * time.Second)
	return nil
}

//export catcloud_go_stop_tun
func catcloud_go_stop_tun() {
	stopTun()

	bridgeMu.Lock()
	stopControllerLocked()
	bridgeMu.Unlock()

	closeAllTrackedConnections()
	resolver.ResetConnection()
	triggerForceGcAsync()
}

//export catcloud_go_update_system_dns
func catcloud_go_update_system_dns(dnsCsv *C.char) {
	servers := parseSystemDNSCSV(C.GoString(dnsCsv))
	dns.UpdateSystemDNS(servers)
	dns.FlushCacheWithDefaultResolver()
}

//export catcloud_go_reset_network
func catcloud_go_reset_network() {
	iface.FlushCache()
	resolver.ClearCache()
	resolver.ResetConnection()
	closeAllTrackedConnections()
}

//export catcloud_go_force_gc
func catcloud_go_force_gc() {
	triggerForceGcAsync()
}

func main() {}
