package reflecttun

import (
	"io"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"

	"github.com/tailscale/wireguard-go/tun"
)

// rxQueueSize bounds the number of reflected packets waiting to be read by
// WireGuard. SideStore traffic (RSD, lockdown, app installs) is low-rate, so
// a modest queue is plenty while keeping memory bounded.
const rxQueueSize = 256

// Stats holds packet counters for diagnostics. The counters are updated
// atomically from the WireGuard I/O goroutines.
type Stats struct {
	Reflected uint64
	Dropped   uint64
}

// Device is an in-memory tun.Device that reflects IPv4 packets between
// deviceIP and nodeIP.
//
// Data path:
//
//	WireGuard decrypt -> Write() -> swap src/dst -> rx queue -> Read()
//	-> WireGuard encrypt -> Tailnet
//
// Direction convention (per the tun.Device contract):
//
//	Write is the entry point for packets WireGuard decrypted and wants to
//	deliver "to the OS". Read is what WireGuard polls for packets that
//	should be sent out to the Tailnet.
type Device struct {
	deviceIP netip.Addr
	nodeIP   netip.Addr

	rx     chan []byte
	events chan tun.Event
	done   chan struct{}

	closeOnce sync.Once
	reflected atomic.Uint64
	dropped   atomic.Uint64
}

var _ tun.Device = (*Device)(nil)

// New creates a reflecting tun.Device. deviceIP is the iPhone's Tailscale
// IPv4 address; nodeIP must be deviceIP+1, enforced by the caller.
func New(deviceIP, nodeIP netip.Addr) *Device {
	d := &Device{
		deviceIP: deviceIP,
		nodeIP:   nodeIP,
		rx:       make(chan []byte, rxQueueSize),
		events:   make(chan tun.Event, 1),
		done:     make(chan struct{}),
	}
	d.events <- tun.EventUp
	return d
}

// Stats returns a snapshot of the packet counters.
func (d *Device) Stats() Stats {
	return Stats{
		Reflected: d.reflected.Load(),
		Dropped:   d.dropped.Load(),
	}
}

// File implements tun.Device. There is no kernel TUN fd.
func (d *Device) File() *os.File {
	return nil
}

// Name implements tun.Device.
func (d *Device) Name() (string, error) {
	return "sidestore-reflector", nil
}

// MTU implements tun.Device. 1280 matches Tailscale's standard MTU.
func (d *Device) MTU() (int, error) {
	return 1280, nil
}

// BatchSize implements tun.Device. Batching is deliberately not
// implemented; correctness first.
func (d *Device) BatchSize() int {
	return 1
}

// Events implements tun.Device. The device is always up until Close.
func (d *Device) Events() <-chan tun.Event {
	return d.events
}

// Write implements tun.Device. It receives decrypted packets from
// WireGuard, reflects the ones that match the configured device/node pair,
// and queues them for Read.
//
// Packets are always copied: ownership of the caller's buffers is not
// guaranteed to transfer.
func (d *Device) Write(bufs [][]byte, offset int) (int, error) {
	written := 0
	for _, buf := range bufs {
		if offset < 0 || offset > len(buf) {
			return written, io.ErrShortBuffer
		}
		pkt := append([]byte(nil), buf[offset:]...)
		pkt, ok := reflectIPv4(
			pkt,
			d.deviceIP,
			d.nodeIP,
		)
		if !ok {
			d.dropped.Add(1)
			written++
			continue
		}
		select {
		case d.rx <- pkt:
			d.reflected.Add(1)
			written++
		case <-d.done:
			return written, os.ErrClosed
		}
	}
	return written, nil
}

// Read implements tun.Device. It blocks until a reflected packet is
// available or the device is closed.
func (d *Device) Read(
	bufs [][]byte,
	sizes []int,
	offset int,
) (int, error) {
	if len(bufs) == 0 || len(sizes) == 0 {
		return 0, io.ErrShortBuffer
	}
	select {
	case <-d.done:
		return 0, os.ErrClosed
	case pkt := <-d.rx:
		if offset < 0 || offset+len(pkt) > len(bufs[0]) {
			return 0, io.ErrShortBuffer
		}
		copy(bufs[0][offset:], pkt)
		sizes[0] = len(pkt)
		return 1, nil
	}
}

// Close implements tun.Device.
//
// rx is intentionally never closed: closing it could race with concurrent
// Write calls and panic on send-to-closed-channel. Read and Write observe
// done instead and unblock with os.ErrClosed.
func (d *Device) Close() error {
	d.closeOnce.Do(func() {
		close(d.done)
		close(d.events)
	})
	return nil
}
