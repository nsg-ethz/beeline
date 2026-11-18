package dialer

import (
	"net"
	"sync"
	"testing"
	"time"
)

// countConns accepts connections on a fresh port until the test ends and
// reports how many arrived.
func countConns(t *testing.T) (string, func() int) {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { l.Close() })

	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			// held open, a closed connection would be dialed again and counted twice
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
	})

	return l.Addr().String(), func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(conns)
	}
}

// waitForConns waits until want connections arrived, and then a little longer
// for any surplus one to show up as well. The server never answers the HTTP/2
// handshake, but gRPC only gives up on it after 20s.
func waitForConns(count func() int, want int) int {
	deadline := time.Now().Add(5 * time.Second)
	for count() < want && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	return count()
}

func TestDialPoolOpensEveryConnection(t *testing.T) {
	for _, conns := range []int{2, 16} {
		addr, count := countConns(t)

		cc, err := DialPool(addr, conns)
		if err != nil {
			t.Fatalf("DialPool(%d): %v", conns, err)
		}
		t.Cleanup(func() { cc.Close() })
		// round_robin connects to every address, but only once asked to
		cc.Connect()

		if got := waitForConns(count, conns); got != conns {
			t.Errorf("DialPool(%d) opened %d connections", conns, got)
		}
	}
}

func TestDialPoolOfOneIsASingleConnection(t *testing.T) {
	addr, count := countConns(t)

	cc, err := DialPool(addr, 1)
	if err != nil {
		t.Fatalf("DialPool(1): %v", err)
	}
	t.Cleanup(func() { cc.Close() })
	cc.Connect()

	if got := waitForConns(count, 1); got != 1 {
		t.Errorf("DialPool(1) opened %d connections", got)
	}
}
