// Command sidestore-reflector runs a single-process, single-binary Tailscale
// reflector node for SideStore 0.6.3+.
//
// SideStore's minimuxer treats the Tailscale peer as deviceIP+1. This program
// joins your tailnet as an embedded tsnet node and reflects every IPv4 packet
// it receives back with source and destination swapped, so an iPhone can talk
// to its own local services through the reflector without ever tearing down
// the Tailscale VPN interface.
//
// Reflection is open: any peer that reaches this node gets its packets
// bounced, with no per-device allowlist. Only run it in a tailnet (or behind
// ACLs) where that is acceptable. SideStore itself always dials
// <iPhone IP> + 1, so this node's Tailscale IPv4 must still be the iPhone's
// IP + 1 (set once in the Tailscale Admin Console).
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

	tunDev := reflecttun.New()

	srv := &tsnet.Server{
		Dir:      stateDir,
		Hostname: defaultHostname,
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

	log.Printf("reflector up: hostname=%s state=%s ips=%v", defaultHostname, stateDir, status.TailscaleIPs)
	log.Printf("SideStore dials <iPhone IP> + 1: make sure this node's IPv4 is the iPhone's IP + 1 (Tailscale Admin Console)")

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
