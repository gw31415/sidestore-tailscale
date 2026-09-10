// Package reflecttun provides an in-memory tun.Device that reflects IPv4
// packets between a SideStore device and the reflector's own Tailscale node.
//
// SideStore 0.6.3+ derives its minimuxer peer address as device IP + 1, so
// the reflector node must own that address inside the Tailnet. Every packet
// the iPhone sends to the reflector (dst == node IP) is bounced back with
// the IPv4 source and destination swapped, which makes the packet appear on
// the iPhone as traffic from the node addressed to the device itself. Ports
// and payloads are never touched, so transport checksums stay valid.
package reflecttun

import (
	"encoding/binary"
	"net/netip"
)

// reflectIPv4 swaps the source and destination IPv4 addresses of pkt in place.
//
// It only reflects packets that match the configured pair exactly:
//
//	src == deviceIP (the iPhone) and dst == nodeIP (this reflector node)
//
// Anything else — IPv6, malformed IPv4, non-Tailscale sources, wrong
// destinations — is rejected so other Tailnet peers cannot use the reflector.
//
// The returned slice aliases pkt and is trimmed to the IPv4 total length.
// The second return value reports whether the packet was reflected.
//
// Swapping only src/dst keeps every checksum valid: the IPv4 header checksum
// is a one's-complement sum that is invariant under exchanging the src and
// dst address words, and TCP/UDP checksums include the pseudo-header, whose
// address fields are likewise merely exchanged.
func reflectIPv4(pkt []byte, deviceIP, nodeIP netip.Addr) ([]byte, bool) {
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
	src := netip.AddrFrom4([4]byte{
		pkt[12], pkt[13], pkt[14], pkt[15],
	})
	dst := netip.AddrFrom4([4]byte{
		pkt[16], pkt[17], pkt[18], pkt[19],
	})
	if src != deviceIP || dst != nodeIP {
		return nil, false
	}
	var tmp [4]byte
	copy(tmp[:], pkt[12:16])
	copy(pkt[12:16], pkt[16:20])
	copy(pkt[16:20], tmp[:])
	return pkt[:totalLen], true
}
