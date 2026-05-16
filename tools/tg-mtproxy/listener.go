// listener.go — Windows replacement for z2k's Linux SO_ORIGINAL_DST path.
//
// On Linux, mtproxy-client retrieves the original (pre-REDIRECT) dst via
// getsockopt(SO_ORIGINAL_DST) — info preserved by iptables conntrack.
// On Windows we don't have that: WinDivert NAT in nat.go bookkeeps
// (srcIP, srcPort) → origDst into natTab, and here we look it up by
// the accepted connection's RemoteAddr (= the client's original src).
//
// Signature matches the Linux implementation in z2k so tunnel.go can stay
// unmodified.

package main

import (
	"errors"
	"net"
)

// getOriginalDst returns the original destination of a NAT'd incoming
// connection. natTab must already contain the entry (populated when the
// SYN was captured in nat.go).
func getOriginalDst(conn *net.TCPConn) (net.IP, int, error) {
	remote, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return nil, 0, errors.New("RemoteAddr is not *net.TCPAddr")
	}
	ip, port, ok := lookupOriginalDst(remote)
	if !ok {
		return nil, 0, errors.New("no NAT entry for " + remote.String() +
			" — WinDivert filter not active or peer is not a NAT'd TG client")
	}
	return ip, port, nil
}
