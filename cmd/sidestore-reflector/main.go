// Command sidestore-reflector runs a single-process, single-binary Tailscale
// reflector node for SideStore 0.6.3+.
//
// SideStore's minimuxer treats the Tailscale peer as deviceIP+1. This program
// embeds Tailscale via tsnet with a custom in-memory tun.Device that swaps the
// IPv4 source and destination of every packet from the configured iPhone, so
// the iPhone can talk to its own local services through the reflector without
// ever tearing down the Tailscale VPN interface.
//
// No Docker, no tailscaled, no /dev/net/tun, no root, no CAP_NET_ADMIN, no
// iptables: just a regular user process with a persistent state directory.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"sidestore-reflector/internal/reflecttun"

	"tailscale.com/tsnet"
)

const (
	defaultHostname = "sidestore-reflector"
	statsInterval   = 10 * time.Second
)

var (
	deviceIPFlag = flag.String("device-ip", "", "iPhone's Tailscale IPv4 address (required)")
	hostnameFlag = flag.String("hostname", defaultHostname, "Tailscale node name")
	stateDirFlag = flag.String("state-dir", "", "tsnet state directory (default "+defaultStateDirHint()+")")
	verboseFlag  = flag.Bool("verbose", false, "enable diagnostic logging")
)

func main() {
	log.SetFlags(log.LstdFlags)
	flag.Parse()

	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if *deviceIPFlag == "" {
		fmt.Fprintln(os.Stderr, "--device-ip is required")
		flag.Usage()
		os.Exit(2)
	}

	deviceIP, nodeIP, err := resolveAddresses(*deviceIPFlag)
	if err != nil {
		return err
	}
	fmt.Printf("iPhone Tailscale IPv4 : %s\n", deviceIP)
	fmt.Printf("Required reflector IP : %s\n", nodeIP)

	stateDir, err := resolveStateDir(*stateDirFlag)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("creating state directory %s: %w", stateDir, err)
	}

	authKey := os.Getenv("TS_AUTHKEY")
	if authKey == "" {
		log.Printf("TS_AUTHKEY is not set; fine for an already-enrolled node, " +
			"but the first run needs one to join the tailnet")
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	tunDev := reflecttun.New(deviceIP, nodeIP)

	srv := &tsnet.Server{
		Dir:      stateDir,
		Hostname: *hostnameFlag,
		AuthKey:  authKey,
		Tun:      tunDev,
	}
	// UserLogf carries user-facing messages such as the interactive login
	// URL, so it always goes to stderr. Logf is the verbose backend firehose.
	srv.UserLogf = log.Printf
	if *verboseFlag {
		srv.Logf = log.Printf
	}

	status, err := srv.Up(ctx)
	if err != nil {
		tunDev.Close()
		srv.Close()
		if errors.Is(err, context.Canceled) {
			// SIGINT/SIGTERM while still enrolling: not a failure.
			log.Printf("shutdown before the node finished coming up: %v", err)
			log.Printf("reflected=%d dropped=%d", tunDev.Stats().Reflected, tunDev.Stats().Dropped)
			return nil
		}
		return fmt.Errorf("bringing up tsnet node: %w", err)
	}

	// The control plane assigns Tailscale IPs; a tsnet node cannot pick its
	// own. Refuse to forward anything unless this node really owns
	// deviceIP+1, because that is the address SideStore will dial.
	actual, ok := findIPv4(status.TailscaleIPs)
	if !ok {
		tunDev.Close()
		srv.Close()
		return fmt.Errorf("tsnet node has no Tailscale IPv4")
	}
	if actual != nodeIP {
		tunDev.Close()
		srv.Close()
		log.Fatalf(`
reflector has wrong Tailscale IPv4.
iPhone:
    %s
Required reflector IP:
    %s
Current reflector IP:
    %s
Open the Tailscale Admin Console,
edit this machine's IPv4 address to %s,
then restart sidestore-reflector.
`, deviceIP, nodeIP, actual, nodeIP)
	}

	log.Printf("reflector up: hostname=%s state=%s", *hostnameFlag, stateDir)
	log.Printf("reflecting %s <-> %s (waiting for packets)", deviceIP, nodeIP)

	if *verboseFlag {
		go periodicStats(ctx, tunDev)
	}

	<-ctx.Done()
	log.Printf("shutting down")

	// Close the TUN first so any Read blocked in the engine unblocks with
	// os.ErrClosed before the engine itself is torn down.
	tunDev.Close()
	if err := srv.Close(); err != nil {
		log.Printf("tsnet shutdown: %v", err)
	}

	st := tunDev.Stats()
	log.Printf("reflected=%d dropped=%d", st.Reflected, st.Dropped)
	return nil
}

// resolveAddresses parses the device IP and derives the reflector node IP as
// deviceIP+1, validating that both fall inside Tailscale's CGNAT range.
func resolveAddresses(deviceIPStr string) (deviceIP, nodeIP netip.Addr, err error) {
	deviceIP, err = netip.ParseAddr(deviceIPStr)
	if err != nil || !deviceIP.Is4() {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf(
			"--device-ip must be an IPv4 address, got %q", deviceIPStr)
	}
	nodeIP = deviceIP.Next()

	tailscaleRange := netip.MustParsePrefix("100.64.0.0/10")
	if !tailscaleRange.Contains(deviceIP) {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf(
			"--device-ip %s is not inside the Tailscale CGNAT range %s",
			deviceIP, tailscaleRange)
	}
	if !tailscaleRange.Contains(nodeIP) {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf(
			"reflector IP %s (device IP + 1) is not inside the Tailscale CGNAT range %s",
			nodeIP, tailscaleRange)
	}
	return deviceIP, nodeIP, nil
}

// findIPv4 returns the first IPv4 address in addrs.
func findIPv4(addrs []netip.Addr) (netip.Addr, bool) {
	for _, addr := range addrs {
		if addr.Is4() {
			return addr, true
		}
	}
	return netip.Addr{}, false
}

func defaultStateDirHint() string {
	if dir, err := defaultStateDir(); err == nil {
		return dir
	}
	return "~/.local/state/sidestore-reflector"
}

func defaultStateDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if runtime.GOOS == "windows" {
		// %USERPROFILE%\AppData\Local\sidestore-reflector
		return filepath.Join(home, "AppData", "Local", "sidestore-reflector"), nil
	}
	return filepath.Join(home, ".local", "state", "sidestore-reflector"), nil
}

func resolveStateDir(dir string) (string, error) {
	if dir == "" {
		return defaultStateDir()
	}
	if len(dir) >= 2 && dir[:2] == "~/" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expanding %q: %w", dir, err)
		}
		dir = filepath.Join(home, dir[2:])
	}
	return filepath.Clean(dir), nil
}

func periodicStats(ctx context.Context, d *reflecttun.Device) {
	t := time.NewTicker(statsInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			st := d.Stats()
			log.Printf("reflected=%d dropped=%d", st.Reflected, st.Dropped)
		}
	}
}
