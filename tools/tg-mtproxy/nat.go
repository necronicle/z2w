// nat.go — WinDivert-based bidirectional NAT.
//
// Mirrors Linux iptables -t nat REDIRECT for Telegram DC TCP/443
// outbound + reply-side rewrite. Without this z2k's mtproxy-client
// would never see TG traffic (TCP stack routes it straight to the WAN).
//
// Flow:
//
//   1. Client app opens TCP to TG_IP:443 (any source port chosen by kernel).
//   2. WinDivert captures the outbound packet at NETWORK layer (filter
//      matches outbound + tcp + dst-port==443 + dst-addr in TG_CIDRs).
//   3. SYN saves (srcIP, srcPort) → (origDstIP, 443) in natTab.
//   4. We rewrite the packet's dst → 127.0.0.1:1443, recalc checksums,
//      re-inject with Loopback=true so the kernel routes it via lo.
//   5. Local listener (:1443) accepts. clientConn.RemoteAddr() is the
//      original src — we look it up in natTab → origDst → CONNECT
//      payload into the WS tunnel.
//   6. Reply path: listener writes back to clientConn. Reply packet
//      has src=127.0.0.1:1443. WinDivert captures it (second clause
//      of the filter). We look up natTab by dst (client side) → origDst
//      → rewrite src to TG_IP:443 so the client's TCP stack accepts it.
//
// natTab uses (srcIP, srcPort) → origDst as key. srcPort alone wouldn't
// be unique on multi-NIC hosts. TTL evicts stale entries via the FIN/RST
// path; on bare timeout we drop after natEntryTTL.

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/imgk/divert-go"
)

// Canonical Telegram MTProto CIDR set. Identical to the Linux S98tg-tunnel
// hardcode and the iptables -t nat REDIRECT range. Update both sides in
// lockstep when Telegram adds DCs.
var tgCIDRs = []string{
	"91.105.192.0/23",
	"91.108.4.0/22",
	"91.108.8.0/22",
	"91.108.12.0/22",
	"91.108.16.0/22",
	"91.108.20.0/22",
	"91.108.56.0/22",
	"95.161.64.0/20",
	"149.154.160.0/20",
	"185.76.151.0/24",
}

const (
	localRelayIPv4 = "127.0.0.1"
	localRelayPort = 1443
	natEntryTTL    = 5 * time.Minute
)

// natKey is the client's ephemeral source port. Since z2w runs on the
// client machine itself, srcPort alone is unique per active TCP flow
// (Windows guarantees uniqueness across local-binds during a port's
// lifetime). Keying on port only also dodges the awkward asymmetry that
// the forward path captures the real LAN IP while the listener sees
// 127.0.0.1 (we rewrite both src and dst to localhost — see
// natCaptureLoop below).
type natKey uint16

type natEntry struct {
	OrigDstIP   [4]byte // TG DC IPv4
	OrigDstPort uint16  // always 443 (TG MTProto) but kept generic
	LocalSrcIP  [4]byte // client's LAN IP — needed to rewrite reverse path
	LastSeen    time.Time
}

var (
	natMu  sync.RWMutex
	natTab = map[natKey]*natEntry{}
)

// lookupOriginalDst is called by the local listener after Accept().
// remote.Port is the original client ephemeral port (preserved through
// NAT rewrite).
func lookupOriginalDst(remote *net.TCPAddr) (net.IP, int, bool) {
	if remote == nil {
		return nil, 0, false
	}
	natMu.RLock()
	e, ok := natTab[natKey(remote.Port)]
	natMu.RUnlock()
	if !ok {
		return nil, 0, false
	}
	return net.IPv4(e.OrigDstIP[0], e.OrigDstIP[1], e.OrigDstIP[2], e.OrigDstIP[3]),
		int(e.OrigDstPort), true
}

// startNAT opens WinDivert with our filter, spawns the capture/rewrite
// goroutine, and a janitor for stale natTab entries. Returns after the
// handle is open (or err on failure).
func startNAT() error {
	filter := buildWinDivertFilter()
	if *verbose {
		log.Printf("WinDivert filter: %s", filter)
	}

	handle, err := divert.Open(filter, divert.LayerNetwork, int16(0), divert.FlagDefault)
	if err != nil {
		return fmt.Errorf("WinDivertOpen: %w (ensure WinDivert.dll + WinDivert64.sys are alongside the .exe and process is admin)", err)
	}

	go natCaptureLoop(handle)
	go natJanitor()
	return nil
}

func buildWinDivertFilter() string {
	parts := make([]string, 0, len(tgCIDRs)+1)
	for _, c := range tgCIDRs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		lo := n.IP.To4()
		hi := make(net.IP, 4)
		for i := 0; i < 4; i++ {
			hi[i] = lo[i] | ^n.Mask[i]
		}
		parts = append(parts, fmt.Sprintf(
			"(ip.DstAddr >= %s and ip.DstAddr <= %s)",
			lo.String(), hi.String()))
	}
	// Two clauses joined by OR:
	//   (1) outbound to TG DC IPv4 on TCP/443 — to capture client SYNs
	//   (2) reply path: outbound (loopback frame) from 127.0.0.1:1443
	out := "(outbound and tcp and tcp.DstPort == 443 and (" + strings.Join(parts, " or ") + "))"
	reply := "(outbound and tcp and ip.SrcAddr == 127.0.0.1 and tcp.SrcPort == 1443)"
	return out + " or " + reply
}

func natCaptureLoop(h *divert.Handle) {
	buf := make([]byte, 1500)
	var addr divert.Address
	for {
		n, err := h.Recv(buf, &addr)
		if err != nil {
			log.Printf("WinDivertRecv: %v", err)
			continue
		}
		pkt := buf[:int(n)]
		if len(pkt) < 20 {
			_, _ = h.Send(pkt, &addr)
			continue
		}
		// IPv4 only.
		if pkt[0]>>4 != 4 {
			_, _ = h.Send(pkt, &addr)
			continue
		}
		ihl := int(pkt[0]&0x0F) * 4
		if len(pkt) < ihl+20 {
			_, _ = h.Send(pkt, &addr)
			continue
		}
		// Only TCP (proto 6).
		if pkt[9] != 6 {
			_, _ = h.Send(pkt, &addr)
			continue
		}
		tcp := pkt[ihl:]

		var srcIP, dstIP [4]byte
		copy(srcIP[:], pkt[12:16])
		copy(dstIP[:], pkt[16:20])
		srcPort := binary.BigEndian.Uint16(tcp[0:2])
		dstPort := binary.BigEndian.Uint16(tcp[2:4])
		flags := tcp[13]

		switch {
		case dstPort == 443:
			// Forward path: client → TG_IP:443.
			//
			// On SYN, snapshot (LAN IP, orig TG IP) so the reverse path can
			// rewrite the reply's src+dst back to what the client's TCP
			// stack expects. Rewrite BOTH src and dst to 127.0.0.1 so the
			// kernel routes the packet through the loopback adapter — a
			// real-LAN src with a loopback dst is rejected by Windows
			// (loopback only accepts 127.0.0.0/8 source). client_src_port
			// is preserved as the flow identifier (used to look up the
			// natTab entry from listener.Accept().RemoteAddr.Port).
			isSYN := flags&0x02 != 0
			if isSYN {
				natMu.Lock()
				natTab[natKey(srcPort)] = &natEntry{
					OrigDstIP:   dstIP,
					OrigDstPort: dstPort,
					LocalSrcIP:  srcIP,
					LastSeen:    time.Now(),
				}
				natMu.Unlock()
				if *verbose {
					log.Printf("NAT: SYN %s:%d → %s:%d  (intercept → 127.0.0.1:%d)",
						ipStr(srcIP), srcPort, ipStr(dstIP), dstPort, localRelayPort)
				}
			}
			pkt[12], pkt[13], pkt[14], pkt[15] = 127, 0, 0, 1 // src → 127.0.0.1
			pkt[16], pkt[17], pkt[18], pkt[19] = 127, 0, 0, 1 // dst → 127.0.0.1
			binary.BigEndian.PutUint16(tcp[2:4], localRelayPort)
			// src_port preserved (flow id)

		case srcPort == localRelayPort &&
			srcIP[0] == 127 && srcIP[1] == 0 && srcIP[2] == 0 && srcIP[3] == 1:
			// Reply path: 127.0.0.1:1443 → 127.0.0.1:ephem. Look up the
			// natTab entry by dst_port (= client's original ephemeral
			// port) and rewrite the packet's src to look like a reply
			// from TG_IP:443 and the dst to the client's real LAN IP —
			// otherwise the client's socket would discard it.
			key := natKey(dstPort)
			natMu.RLock()
			e, ok := natTab[key]
			natMu.RUnlock()
			if !ok {
				// Unrelated loopback traffic on port 1443. Pass through.
				_, _ = h.Send(pkt, &addr)
				continue
			}
			natMu.Lock()
			e.LastSeen = time.Now()
			natMu.Unlock()
			copy(pkt[12:16], e.OrigDstIP[:])  // src → orig TG_IP
			copy(pkt[16:20], e.LocalSrcIP[:]) // dst → client LAN IP
			binary.BigEndian.PutUint16(tcp[0:2], e.OrigDstPort)
			if flags&0x05 != 0 { // FIN|RST → evict
				natMu.Lock()
				delete(natTab, key)
				natMu.Unlock()
			}
		}

		// Recalc IPv4 + TCP checksums. WinDivert helper does both.
		divert.CalcChecksums(pkt, &addr, 0)

		if _, err := h.Send(pkt, &addr); err != nil {
			log.Printf("WinDivertSend: %v", err)
		}
	}
}

func natJanitor() {
	t := time.NewTicker(natEntryTTL / 2)
	defer t.Stop()
	for range t.C {
		cutoff := time.Now().Add(-natEntryTTL)
		natMu.Lock()
		for k, e := range natTab {
			if e.LastSeen.Before(cutoff) {
				delete(natTab, k)
			}
		}
		natMu.Unlock()
	}
}

func ipStr(b [4]byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

// Keep go vet quiet about unused error in non-Windows lint runs.
var _ = errors.New
