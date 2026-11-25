//go:build android && cmfa

package main

import (
	"fmt"
	"net/netip"
	"sync"
	"syscall"

	constant "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing_tun"
	"github.com/metacubex/mihomo/tunnel"
)

const (
	defaultTunMTU = 9000
	minTunMTU     = 1280
	maxTunMTU     = 65535
)

var (
	tunMu     sync.Mutex
	activeTun *sing_tun.Listener
)

func attachTun(tunFd int, mtu int) error {
	tunMu.Lock()
	defer tunMu.Unlock()

	if tunFd <= 0 {
		return fmt.Errorf("invalid tunFd: %d", tunFd)
	}

	if !isConfigPrepared() {
		// Kotlin already called detachFd() before invoking nativeAttachTun.
		// Since sing_tun.New will not be called, we own tunFd and must close it here.
		_ = syscall.Close(tunFd)
		return fmt.Errorf("config must be prepared via nativePrepareConfig before nativeAttachTun")
	}

	if mtu <= 0 {
		mtu = defaultTunMTU
	} else if mtu < minTunMTU {
		mtu = minTunMTU
	} else if mtu > maxTunMTU {
		mtu = maxTunMTU
	}

	// Close any existing TUN listener before attaching the new descriptor.
	if activeTun != nil {
		_ = activeTun.Close()
		activeTun = nil
	}

	tunCfg := LC.Tun{
		Enable:              true,
		Device:              "catcloud",
		Stack:               constant.TunSystem,
		DNSHijack:           []string{"any:53", "tcp://any:53"},
		AutoRoute:           false,
		AutoDetectInterface: false,
		Inet4Address:        []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")},
		MTU:                 uint32(mtu),
		FileDescriptor:      tunFd,
	}

	// Security & FD-ownership invariant:
	// - tunFd MUST come strictly from Android VpnService.Builder.establish().detachFd()
	//   inside same-UID CatCloudVpnService (after tunFd > 0, configPrepared, and clamped MTU checks).
	//   NEVER pass unvalidated external parameters or arbitrary file descriptors directly to sing_tun.New.
	// - Ownership of tunFd transfers to sing_tun.New (which wraps it in os.NewFile and
	//   closes it inside its own defer l.Close() if stack startup fails). Do not add a
	//   duplicate defer syscall.Close(tunFd) here to prevent double-close / fdsan SIGABRT.
	listener, err := sing_tun.New(tunCfg, tunnel.Tunnel)
	if err != nil {
		return fmt.Errorf("sing_tun.New failed: %w", err)
	}

	activeTun = listener
	return nil
}

func stopTun() {
	tunMu.Lock()
	defer tunMu.Unlock()

	if activeTun != nil {
		_ = activeTun.Close()
		activeTun = nil
	}
}
