// Command sidestore-reflector runs a single-process, single-binary Tailscale
// reflector node for SideStore 0.6.3+.
//
// SideStore can use this program as an explicit remote endpoint. It joins your
// tailnet as an embedded tsnet node and reflects every IPv4 packet it receives
// back with source and destination swapped, so an iPhone can talk to its own
// local services through the reflector without tearing down Tailscale.
//
// Reflection is open: any peer that reaches this node gets its packets
// bounced, with no per-device allowlist. Only run it in a tailnet (or behind
// ACLs) where that is acceptable.
//
// No Docker, no tailscaled, no /dev/net/tun, no root, no CAP_NET_ADMIN, no
// iptables: just a regular user process with a persistent state directory.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"sidestore-reflector/internal/reflecttun"

	"tailscale.com/tsnet"
)

const defaultHostname = "sidestore-reflector"

func main() {
	log.SetFlags(log.LstdFlags)
	if len(os.Args) != 1 {
		log.Fatal("sidestore-reflector accepts no arguments")
	}

	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	// tsnet otherwise consumes inherited auth-key variables automatically.
	// This program deliberately supports interactive enrollment only.
	for _, name := range []string{"TS_AUTHKEY", "TS_AUTH_KEY"} {
		if err := os.Unsetenv(name); err != nil {
			return fmt.Errorf("clearing %s: %w", name, err)
		}
	}

	stateDir, err := stateDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("creating state directory %s: %w", stateDir, err)
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
		Tun:      tunDev,
	}
	// UserLogf carries user-facing messages such as the interactive login URL.
	srv.UserLogf = log.Printf

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
	log.Printf("configure SideStore Remote Endpoint with this node's Tailscale IPv4")

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

func stateDir() (string, error) {
	// systemd sets STATE_DIRECTORY for the directory created by
	// StateDirectory=. Outside systemd, keep state in the user's home.
	if dir := os.Getenv("STATE_DIRECTORY"); dir != "" {
		return filepath.Clean(dir), nil
	}

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
