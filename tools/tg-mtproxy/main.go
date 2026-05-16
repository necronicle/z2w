// tg-mtproxy — Windows port of z2k's mtproxy-client + WinDivert NAT.
//
// Architecture (mirrors Linux z2k S98tg-tunnel exactly):
//
//   Linux:   iptables -t nat REDIRECT TG_CIDRs:443 → 127.0.0.1:1443
//            mtproxy-client reads getsockopt(SO_ORIGINAL_DST) per accept
//            forwards via WSS [streamID u16 BE][type u8][payload] to vps-relay
//
//   Windows: WinDivert outbound TCP capture for TG_CIDRs:443
//            Bidirectional NAT rewrites dst → 127.0.0.1:1443 (and reverse)
//            Listener looks up natTab[clientIP:clientPort] → orig dst
//            Same WSS wire protocol, same auth, same TG CIDR set
//
// Configuration via env vars (set by z2w GUI):
//   Z2W_TUNNEL_URL    — wss URL (default: wss://213.176.74.63.nip.io/ws)
//   Z2W_TUNNEL_SECRET — hex secret for HMAC-SHA256(secret, secret) auth
//
// CLI flags override env, for ad-hoc testing.
//
// Verbose logging is ON by default — z2w drains stderr to z2w-tg.log
// with rolling rotation, so the log is rate-limited at the consumer
// not at the producer. -v=false suppresses per-stream chatter.

package main

import (
	"flag"
	"log"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// wsWriter serializes all writes to a single WebSocket. gorilla/websocket
// supports only one concurrent writer. Shared between tunnel.go's read
// loop, the ping ticker, and per-stream forwarders.
type wsWriter struct {
	ws *websocket.Conn
	mu sync.Mutex
}

func (w *wsWriter) WriteMessage(messageType int, data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return w.ws.WriteMessage(messageType, data)
}

func (w *wsWriter) WriteControl(messageType int, data []byte, deadline time.Time) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.ws.WriteControl(messageType, data, deadline)
}

// connSemaphore limits concurrent client connections (bounded by maxConns).
var connSemaphore chan struct{}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

var (
	listenAddr = flag.String("listen", "127.0.0.1:1443",
		"Local listen address (must match WinDivert NAT target)")
	tunnelURL = flag.String("tunnel-url",
		envOr("Z2W_TUNNEL_URL", "wss://213.176.74.63.nip.io/ws"),
		"Tunnel relay WebSocket URL")
	tunnelSecret = flag.String("tunnel-secret",
		envOr("Z2W_TUNNEL_SECRET",
			"d01f72f9543b29da4e3724b1530c0d11cb30a6f8db15bc0adfe8f2d37b5844b2"),
		"Shared secret for HMAC tunnel auth")
	verbose     = flag.Bool("v", true, "Verbose logging")
	connTimeout = flag.Duration("timeout", 15*time.Minute,
		"Idle connection timeout")
	maxConns = flag.Int("max-conns", 1024,
		"Maximum concurrent client connections")
	noNAT = flag.Bool("no-nat", false,
		"Skip WinDivert NAT (rely on external redirector — for testing only)")
)

func main() {
	log.SetFlags(log.LstdFlags)
	flag.Parse()

	log.Printf("tg-mtproxy: Telegram TCP-over-WSS tunnel client (Windows)")
	log.Printf("listen=%s tunnel=%s", *listenAddr, *tunnelURL)

	connSemaphore = make(chan struct{}, *maxConns)

	if !*noNAT {
		if err := startNAT(); err != nil {
			log.Fatalf("NAT setup failed: %v", err)
		}
		log.Println("NAT: WinDivert intercepting Telegram DC outbound TCP/443")
	} else {
		log.Println("NAT: SKIPPED (--no-nat) — rely on external redirector")
	}

	if err := runTunnel(); err != nil {
		log.Fatal(err)
	}
}
