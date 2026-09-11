// Package reflecttun provides an in-memory tun.Device that reflects IPv4
// packets back to their senders with source and destination swapped.
//
// SideStore uses the reflector node's address as an explicit remote endpoint.
// Every IPv4 packet any peer sends to the reflector is bounced back with the
// IPv4 source and destination swapped, which makes the packet appear on the
// sender as traffic from the node addressed to the sender itself. Ports and
// payloads are never touched, so transport checksums stay valid.
//
// Reflection is deliberately open: any Tailnet peer that reaches the
// reflector gets its packets bounced, with no per-device allowlist. Only run
// this in a Tailnet (or behind ACLs) where that is acceptable.
package reflecttun

import (
	"encoding/binary"
)

// reflectIPv4 swaps the source and destination IPv4 addresses of pkt in place.
//
// Any well-formed IPv4 packet is reflected, regardless of its addresses.
// Malformed IPv4 and non-IPv4 (e.g. IPv6) packets are rejected.
//
// The returned slice aliases pkt and is trimmed to the IPv4 total length.
// The second return value reports whether the packet was reflected.
//
// Swapping only src/dst keeps every checksum valid: the IPv4 header checksum
// is a one's-complement sum that is invariant under exchanging the src and
// dst address words, and TCP/UDP checksums include the pseudo-header, whose
// address fields are likewise merely exchanged.
func reflectIPv4(pkt []byte) ([]byte, bool) {
	if len(pkt) < 20 {
		return nil, false
	}
	if pkt[0]>>4 != 4 {
		return nil, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || ihl > len(pkt) {
		return nil, false
	}
	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if totalLen < ihl || totalLen > len(pkt) {
		return nil, false
	}
	var tmp [4]byte
	copy(tmp[:], pkt[12:16])
	copy(pkt[12:16], pkt[16:20])
	copy(pkt[16:20], tmp[:])
	return pkt[:totalLen], true
}
