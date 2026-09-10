package reflecttun

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"
)

var (
	phoneAddr     = netip.MustParseAddr("100.101.102.103")
	reflectorAddr = netip.MustParseAddr("100.101.102.104")
)

// --- packet construction helpers -------------------------------------------

func onesComplementSum(data []byte) uint32 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	return sum
}

func foldChecksum(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func ipHeaderChecksum(hdr []byte) uint16 {
	return foldChecksum(onesComplementSum(hdr))
}

// tcpPseudoChecksum computes the TCP checksum over the IPv4 pseudo-header
// (src, dst, protocol, TCP length) and the TCP segment.
func tcpPseudoChecksum(ipHdr, tcpSeg []byte) uint16 {
	sum := onesComplementSum(ipHdr[12:20]) // src + dst
	sum += 6                               // IPPROTO_TCP
	sum += uint32(len(tcpSeg))
	sum += onesComplementSum(tcpSeg)
	return foldChecksum(sum)
}

// buildTCPPacket builds a valid IPv4/TCP packet from src to dst with the
// given ports and payload, including correct IPv4 header and TCP checksums.
func buildTCPPacket(src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	totalLen := 20 + 20 + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45 // IPv4, IHL 5
	pkt[1] = 0x00 // DSCP/ECN
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], 0x1234) // ID
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000) // DF
	pkt[8] = 64                                  // TTL
	pkt[9] = 6                                   // IPPROTO_TCP
	s := src.As4()
	d := dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	binary.BigEndian.PutUint16(pkt[10:12], ipHeaderChecksum(pkt[0:20]))

	tcp := pkt[20:]
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	binary.BigEndian.PutUint32(tcp[4:8], 0xdeadbeef) // seq
	binary.BigEndian.PutUint32(tcp[8:12], 0x00000001)
	tcp[12] = 0x50                                 // data offset 5
	tcp[13] = 0x18                                 // PSH|ACK
	binary.BigEndian.PutUint16(tcp[14:16], 0x2000) // window
	copy(tcp[20:], payload)
	binary.BigEndian.PutUint16(tcp[16:18], tcpPseudoChecksum(pkt[0:20], tcp))
	return pkt
}

// --- reflectIPv4 -----------------------------------------------------------

func TestReflectIPv4Swap(t *testing.T) {
	payload := []byte("sidestore-payload")
	pkt := buildTCPPacket(phoneAddr, reflectorAddr, 51000, 62078, payload)

	got, ok := reflectIPv4(pkt)
	if !ok {
		t.Fatal("expected packet to be reflected")
	}
	if len(got) != 40+len(payload) {
		t.Fatalf("length = %d, want %d", len(got), 40+len(payload))
	}
	if src := netip.AddrFrom4([4]byte{got[12], got[13], got[14], got[15]}); src != reflectorAddr {
		t.Errorf("src = %s, want %s", src, reflectorAddr)
	}
	if dst := netip.AddrFrom4([4]byte{got[16], got[17], got[18], got[19]}); dst != phoneAddr {
		t.Errorf("dst = %s, want %s", dst, phoneAddr)
	}
	if sport := binary.BigEndian.Uint16(got[20:22]); sport != 51000 {
		t.Errorf("src port = %d, want 51000", sport)
	}
	if dport := binary.BigEndian.Uint16(got[22:24]); dport != 62078 {
		t.Errorf("dst port = %d, want 62078", dport)
	}
	if string(got[40:]) != string(payload) {
		t.Errorf("payload changed: %q", got[40:])
	}
}

// TestReflectIPv4AnyAddresses pins the open-reflection behavior: any
// well-formed IPv4 packet is bounced, no matter the addresses involved.
func TestReflectIPv4AnyAddresses(t *testing.T) {
	pairs := [][2]netip.Addr{
		{phoneAddr, reflectorAddr},
		{netip.MustParseAddr("100.105.20.30"), netip.MustParseAddr("100.105.20.31")},
		{netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("100.127.255.254")},
		{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")},
	}
	for _, p := range pairs {
		pkt := buildTCPPacket(p[0], p[1], 1234, 5678, []byte("x"))
		got, ok := reflectIPv4(pkt)
		if !ok {
			t.Errorf("packet %s -> %s was not reflected", p[0], p[1])
			continue
		}
		src := netip.AddrFrom4([4]byte{got[12], got[13], got[14], got[15]})
		dst := netip.AddrFrom4([4]byte{got[16], got[17], got[18], got[19]})
		if src != p[1] || dst != p[0] {
			t.Errorf("packet %s -> %s reflected as %s -> %s", p[0], p[1], src, dst)
		}
	}
}

func TestReflectIPv4TrimsTrailingBytes(t *testing.T) {
	pkt := buildTCPPacket(phoneAddr, reflectorAddr, 51000, 62078, []byte("x"))
	pkt = append(pkt, 0xde, 0xad, 0xbe, 0xef) // trailing garbage

	got, ok := reflectIPv4(pkt)
	if !ok {
		t.Fatal("expected packet to be reflected")
	}
	if len(got) != int(binary.BigEndian.Uint16(got[2:4])) {
		t.Fatalf("result not trimmed to total length: %d", len(got))
	}
}

func TestReflectIPv4ChecksumsValid(t *testing.T) {
	payload := []byte("checksum-regression")
	pkt := buildTCPPacket(phoneAddr, reflectorAddr, 51000, 62078, payload)

	ipCKBefore := binary.BigEndian.Uint16(pkt[10:12])
	tcpCKBefore := binary.BigEndian.Uint16(pkt[36:38]) // 20 (IP) + 16 (TCP cksum)

	got, ok := reflectIPv4(pkt)
	if !ok {
		t.Fatal("expected packet to be reflected")
	}

	// Checksum fields must be untouched.
	if ck := binary.BigEndian.Uint16(got[10:12]); ck != ipCKBefore {
		t.Errorf("IPv4 header checksum changed: %04x -> %04x", ipCKBefore, ck)
	}
	if ck := binary.BigEndian.Uint16(got[36:38]); ck != tcpCKBefore {
		t.Errorf("TCP checksum changed: %04x -> %04x", tcpCKBefore, ck)
	}

	// And they must still verify as valid after the address swap.
	ihl := int(got[0]&0x0f) * 4
	hdr := append([]byte(nil), got[:ihl]...)
	hdr[10], hdr[11] = 0, 0
	if got0 := ipHeaderChecksum(hdr); got0 != ipCKBefore {
		t.Errorf("IPv4 header checksum invalid after swap: got %04x, field %04x", got0, ipCKBefore)
	}
	seg := append([]byte(nil), got[ihl:]...)
	seg[16], seg[17] = 0, 0
	if got0 := tcpPseudoChecksum(got[:ihl], seg); got0 != tcpCKBefore {
		t.Errorf("TCP checksum invalid after swap: got %04x, field %04x", got0, tcpCKBefore)
	}
}

func TestReflectIPv4Malformed(t *testing.T) {
	valid := buildTCPPacket(phoneAddr, reflectorAddr, 51000, 62078, []byte("x"))

	tests := []struct {
		name string
		pkt  []byte
	}{
		{"empty", nil},
		{"short", valid[:19]},
		{"ipv6", append([]byte{0x60, 0, 0, 0, 0, 0, 20, 6}, make([]byte, 32)...)},
		{"bad version", func() []byte { p := append([]byte(nil), valid...); p[0] = 0x50; return p }()},
		{"ihl zero", func() []byte { p := append([]byte(nil), valid...); p[0] = 0x40; return p }()},
		{"ihl beyond packet", func() []byte { p := append([]byte(nil), valid...); p[0] = 0x4f; return p }()},
		{"total length below ihl", func() []byte {
			p := append([]byte(nil), valid...)
			p[0] = 0x46 // IHL 6
			binary.BigEndian.PutUint16(p[2:4], 20)
			return p
		}()},
		{"total length beyond packet", func() []byte {
			p := append([]byte(nil), valid...)
			binary.BigEndian.PutUint16(p[2:4], 100)
			return p
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, ok := reflectIPv4(tt.pkt); ok {
				t.Fatal("malformed packet was reflected")
			}
		})
	}
}

// --- Device ----------------------------------------------------------------

// writePacket pushes one packet through Device.Write with the given offset,
// mimicking how WireGuard delivers decrypted packets.
func writePacket(t *testing.T, d *Device, pkt []byte, offset int) {
	t.Helper()
	prefix := make([]byte, offset)
	for i := range prefix {
		prefix[i] = 0xee
	}
	buf := append(append([]byte(nil), prefix...), pkt...)
	n, err := d.Write([][]byte{buf}, offset)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != 1 {
		t.Fatalf("Write returned n = %d, want 1", n)
	}
}

// readPacket pulls one packet out of Device.Read with the given offset.
func readPacket(t *testing.T, d *Device, offset int, size int) []byte {
	t.Helper()
	buf := make([]byte, offset+size+16)
	sizes := make([]int, 1)
	n, err := d.Read([][]byte{buf}, sizes, offset)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n != 1 {
		t.Fatalf("Read returned n = %d, want 1", n)
	}
	return append([]byte(nil), buf[offset:offset+sizes[0]]...)
}

func TestDeviceReflectRoundTrip(t *testing.T) {
	d := New()
	defer d.Close()

	payload := []byte("hello-sidestore")
	pkt := buildTCPPacket(phoneAddr, reflectorAddr, 51000, 62078, payload)

	writePacket(t, d, pkt, 0)
	got := readPacket(t, d, 0, len(pkt))

	want := buildTCPPacket(reflectorAddr, phoneAddr, 51000, 62078, payload)
	if string(got) != string(want) {
		t.Fatalf("reflected packet mismatch\n got: %x\nwant: %x", got, want)
	}
	st := d.Stats()
	if st.Reflected != 1 || st.Dropped != 0 {
		t.Fatalf("stats = %+v, want reflected=1 dropped=0", st)
	}
}

// TestDeviceDoubleReflection reproduces the full SideStore packet flow:
// request and response both bounce off the reflector.
func TestDeviceDoubleReflection(t *testing.T) {
	d := New()
	defer d.Close()

	// PHONE:51000 -> REFLECTOR:62078 (SideStore connects to the "peer").
	writePacket(t, d, buildTCPPacket(phoneAddr, reflectorAddr, 51000, 62078, []byte("req")), 0)
	got := readPacket(t, d, 0, 1280)
	if src := netip.AddrFrom4([4]byte{got[12], got[13], got[14], got[15]}); src != reflectorAddr {
		t.Fatalf("hop 1 src = %s, want %s", src, reflectorAddr)
	}
	if dst := netip.AddrFrom4([4]byte{got[16], got[17], got[18], got[19]}); dst != phoneAddr {
		t.Fatalf("hop 1 dst = %s, want %s", dst, phoneAddr)
	}
	if sport := binary.BigEndian.Uint16(got[20:22]); sport != 51000 {
		t.Fatalf("hop 1 sport = %d, want 51000", sport)
	}
	if dport := binary.BigEndian.Uint16(got[22:24]); dport != 62078 {
		t.Fatalf("hop 1 dport = %d, want 62078", dport)
	}

	// PHONE:62078 -> REFLECTOR:51000 (iPhone local service replies).
	writePacket(t, d, buildTCPPacket(phoneAddr, reflectorAddr, 62078, 51000, []byte("resp")), 0)
	got = readPacket(t, d, 0, 1280)
	if sport := binary.BigEndian.Uint16(got[20:22]); sport != 62078 {
		t.Fatalf("hop 2 sport = %d, want 62078", sport)
	}
	if dport := binary.BigEndian.Uint16(got[22:24]); dport != 51000 {
		t.Fatalf("hop 2 dport = %d, want 51000", dport)
	}
	if string(got[40:]) != "resp" {
		t.Fatalf("hop 2 payload = %q", got[40:])
	}
}

func TestDeviceOffset(t *testing.T) {
	d := New()
	defer d.Close()

	pkt := buildTCPPacket(phoneAddr, reflectorAddr, 51000, 62078, []byte("offset"))

	const offset = 16
	writePacket(t, d, pkt, offset)
	got := readPacket(t, d, offset, len(pkt))

	want := buildTCPPacket(reflectorAddr, phoneAddr, 51000, 62078, []byte("offset"))
	if string(got) != string(want) {
		t.Fatalf("packet not preserved across offset %d\n got: %x\nwant: %x", offset, got, want)
	}
}

func TestDeviceDropsInvalidPackets(t *testing.T) {
	d := New()
	defer d.Close()

	// IPv6.
	writePacket(t, d, append([]byte{0x60, 0, 0, 0, 0, 0, 20, 6}, make([]byte, 32)...), 0)
	// Truncated IPv4.
	writePacket(t, d, []byte{0x45, 0, 0}, 0)

	st := d.Stats()
	if st.Reflected != 0 || st.Dropped != 2 {
		t.Fatalf("stats = %+v, want reflected=0 dropped=2", st)
	}
}

func TestDeviceReadShortBuffer(t *testing.T) {
	d := New()
	defer d.Close()

	writePacket(t, d, buildTCPPacket(phoneAddr, reflectorAddr, 51000, 62078, []byte("x")), 0)

	buf := make([]byte, 10) // too small for the packet
	if n, err := d.Read([][]byte{buf}, make([]int, 1), 0); !errors.Is(err, io.ErrShortBuffer) || n != 0 {
		t.Fatalf("Read with small buffer: n=%d err=%v, want io.ErrShortBuffer", n, err)
	}
	if n, err := d.Read(nil, nil, 0); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("Read with no buffers: n=%d err=%v, want io.ErrShortBuffer", n, err)
	}
}

func TestDeviceWriteInvalidOffset(t *testing.T) {
	d := New()
	defer d.Close()

	pkt := buildTCPPacket(phoneAddr, reflectorAddr, 51000, 62078, []byte("x"))
	if n, err := d.Write([][]byte{pkt}, len(pkt)+1); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("Write offset past end: n=%d err=%v, want io.ErrShortBuffer", n, err)
	}
	if n, err := d.Write([][]byte{pkt}, -1); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("negative offset: n=%d err=%v, want io.ErrShortBuffer", n, err)
	}
}

func TestDeviceCloseUnblocksRead(t *testing.T) {
	d := New()

	type result struct {
		n   int
		err error
	}
	res := make(chan result, 1)
	buf := make([]byte, 2000)
	go func() {
		n, err := d.Read([][]byte{buf}, make([]int, 1), 0)
		res <- result{n, err}
	}()

	// Give the reader a moment to block inside Read.
	time.Sleep(50 * time.Millisecond)
	select {
	case r := <-res:
		t.Fatalf("Read returned before Close: %+v", r)
	default:
	}

	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case r := <-res:
		if !errors.Is(r.err, os.ErrClosed) {
			t.Fatalf("Read after Close: err=%v, want os.ErrClosed", r.err)
		}
		if r.n != 0 {
			t.Fatalf("Read after Close: n=%d, want 0", r.n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Read did not unblock after Close")
	}

	// Repeated Close must be safe.
	if err := d.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestDeviceWriteAfterClose(t *testing.T) {
	d := New()

	// Fill the queue so the send cannot win the select deterministically.
	for i := 0; i < rxQueueSize; i++ {
		writePacket(t, d, buildTCPPacket(phoneAddr, reflectorAddr, 51000, 62078, []byte("fill")), 0)
	}
	d.Close()

	pkt := buildTCPPacket(phoneAddr, reflectorAddr, 51000, 62078, []byte("x"))
	if n, err := d.Write([][]byte{pkt}, 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Write after Close: n=%d err=%v, want os.ErrClosed", n, err)
	}
}

func TestDeviceTrivialMethods(t *testing.T) {
	d := New()
	defer d.Close()

	if f := d.File(); f != nil {
		t.Errorf("File() = %v, want nil", f)
	}
	if name, err := d.Name(); err != nil || name != "sidestore-reflector" {
		t.Errorf("Name() = %q, %v", name, err)
	}
	if mtu, err := d.MTU(); err != nil || mtu != 1280 {
		t.Errorf("MTU() = %d, %v", mtu, err)
	}
	if bs := d.BatchSize(); bs != 1 {
		t.Errorf("BatchSize() = %d, want 1", bs)
	}
	select {
	case ev := <-d.Events():
		if ev != tun.EventUp {
			t.Errorf("event = %v, want EventUp", ev)
		}
	default:
		t.Error("no initial EventUp event")
	}
}
