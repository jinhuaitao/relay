package app

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

const tcpTestTimeout = 1500 * time.Millisecond

func testTCPListener(t *testing.T) *net.TCPListener {
	t.Helper()
	l, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	if err := l.SetDeadline(time.Now().Add(4 * tcpTestTimeout)); err != nil {
		t.Fatal(err)
	}
	return l
}

func testTCPDial(t *testing.T, l *net.TCPListener) *net.TCPConn {
	t.Helper()
	c, err := net.DialTimeout("tcp4", l.Addr().String(), tcpTestTimeout)
	if err != nil {
		t.Fatal(err)
	}
	s := c.(*net.TCPConn)
	t.Cleanup(func() { s.Close() })
	if err := s.SetDeadline(time.Now().Add(tcpTestTimeout)); err != nil {
		t.Fatal(err)
	}
	return s
}

func testTCPAccept(t *testing.T, l *net.TCPListener) *net.TCPConn {
	t.Helper()
	c, err := l.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.SetDeadline(time.Now().Add(tcpTestTimeout)); err != nil {
		t.Fatal(err)
	}
	return c
}

func testTCPTask(t *testing.T, src net.Conn, dst *net.TCPListener, tid string) (*TrafficCounter, <-chan struct{}) {
	t.Helper()
	return testTCPTaskWithContext(t, context.Background(), src, dst, tid)
}

func testTCPTaskWithContext(t *testing.T, ctx context.Context, src net.Conn, dst *net.TCPListener, tid string) (*TrafficCounter, <-chan struct{}) {
	t.Helper()
	target := dst.Addr().String()
	ctr := &TrafficCounter{}
	activeTargets.Store(tid, target)
	agentTraffic.Store(tid, ctr)
	done := make(chan struct{})
	go func() { defer close(done); pipeTCP(ctx, src, tid, 0, "rr") }()
	t.Cleanup(func() {
		src.Close()
		select {
		case <-done:
		case <-time.After(3 * tcpTestTimeout):
			t.Error("pipeTCP did not exit after accepted socket was closed")
		}
		activeTargets.Delete(tid)
		agentTraffic.Delete(tid)
		connCounters.Delete(target)
	})
	return ctr, done
}

func tcpTestWrite(t *testing.T, c *net.TCPConn, want []byte) {
	t.Helper()
	n, err := c.Write(want)
	if err != nil || n != len(want) {
		t.Fatalf("write length=%d want=%d: %v", n, len(want), err)
	}
}

func tcpTestRead(t *testing.T, c *net.TCPConn, want []byte) {
	t.Helper()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("payload mismatch or read failure: %v", err)
	}
}

func tcpTestEOF(t *testing.T, c *net.TCPConn, desc string) {
	t.Helper()
	var b [1]byte
	n, err := c.Read(b[:])
	if n != 0 || err != io.EOF {
		t.Fatalf("%s: expected propagated EOF: n=%d err=%v", desc, n, err)
	}
}

func tcpTestDone(t *testing.T, done <-chan struct{}, target string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(tcpTestTimeout):
		t.Fatal("forwarder did not reclaim the closed pair")
	}
	if value, ok := connCounters.Load(target); !ok || atomic.LoadInt64(value.(*int64)) != 0 {
		t.Fatal("outgoing connection count was not released")
	}
}

func TestTCPHalfCloseReachesBackend(t *testing.T) {
	entry, upstream := testTCPListener(t), testTCPListener(t)
	client := testTCPDial(t, entry)
	_, done := testTCPTask(t, testTCPAccept(t, entry), upstream, t.Name())
	backend := testTCPAccept(t, upstream)
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	tcpTestEOF(t, backend, "client closed its write side before sending data")
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}
	tcpTestEOF(t, client, "backend closed after observing client EOF")
	tcpTestDone(t, done, upstream.Addr().String())
}

func TestTCPTwoHopHalfClosePreservesResponse(t *testing.T) {
	entry, bridge, upstream := testTCPListener(t), testTCPListener(t), testTCPListener(t)
	client := testTCPDial(t, entry)
	entryCtr, entryDone := testTCPTask(t, testTCPAccept(t, entry), bridge, t.Name()+"_entry")
	exitCtr, exitDone := testTCPTask(t, testTCPAccept(t, bridge), upstream, t.Name()+"_exit")
	backend := testTCPAccept(t, upstream)
	payload := bytes.Repeat([]byte("request"), 12000)
	tcpTestWrite(t, client, payload)
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	tcpTestRead(t, backend, payload)
	tcpTestEOF(t, backend, "two-hop backend before replying")
	select {
	case <-entryDone:
		t.Fatal("healthy reverse direction was closed early")
	default:
	}
	reply := bytes.Repeat([]byte("response"), 11000)
	tcpTestWrite(t, backend, reply)
	if err := backend.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	tcpTestRead(t, client, reply)
	tcpTestEOF(t, client, "two-hop client after reading backend response")
	tcpTestDone(t, entryDone, bridge.Addr().String())
	tcpTestDone(t, exitDone, upstream.Addr().String())
	for _, c := range []*TrafficCounter{entryCtr, exitCtr} {
		if atomic.LoadInt64(&c.Tx) != int64(len(payload)) || atomic.LoadInt64(&c.Rx) != int64(len(reply)) {
			t.Fatal("relay traffic counters differ from destination bytes")
		}
	}
}

func TestTCPBackendHalfClosePreservesClientWrites(t *testing.T) {
	entry, upstream := testTCPListener(t), testTCPListener(t)
	client := testTCPDial(t, entry)
	_, done := testTCPTask(t, testTCPAccept(t, entry), upstream, t.Name())
	backend := testTCPAccept(t, upstream)
	greeting := []byte("upstream done writing")
	tcpTestWrite(t, backend, greeting)
	if err := backend.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	tcpTestRead(t, client, greeting)
	tcpTestEOF(t, client, "backend sent EOF first")
	payload := []byte("client may still send data")
	tcpTestWrite(t, client, payload)
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	tcpTestRead(t, backend, payload)
	tcpTestEOF(t, backend, "client also closed its write side")
	tcpTestDone(t, done, upstream.Addr().String())
}

func TestTCPResetReclaimsSilentPeer(t *testing.T) {
	entry, upstream := testTCPListener(t), testTCPListener(t)
	client := testTCPDial(t, entry)
	_, done := testTCPTask(t, testTCPAccept(t, entry), upstream, t.Name())
	backend := testTCPAccept(t, upstream)
	if err := client.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	tcpTestEOF(t, backend, "upstream sees closed peer after client reset")
	tcpTestDone(t, done, upstream.Addr().String())
}

func TestTCPConnectOnlyClosesBothHops(t *testing.T) {
	entry, bridge, upstream := testTCPListener(t), testTCPListener(t), testTCPListener(t)
	client := testTCPDial(t, entry)
	_, entryDone := testTCPTask(t, testTCPAccept(t, entry), bridge, t.Name()+"_entry")
	_, exitDone := testTCPTask(t, testTCPAccept(t, bridge), upstream, t.Name()+"_exit")
	backend := testTCPAccept(t, upstream)
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	tcpTestEOF(t, backend, "connect-only probe should not leave a two-hop upstream established")
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}
	tcpTestDone(t, entryDone, bridge.Addr().String())
	tcpTestDone(t, exitDone, upstream.Addr().String())
}

func testTCPPair(t *testing.T, halfCloseIdle time.Duration) (client, backend *net.TCPConn, done <-chan struct{}) {
	t.Helper()
	entry, upstream := testTCPListener(t), testTCPListener(t)
	client = testTCPDial(t, entry)
	src := testTCPAccept(t, entry)
	dst := testTCPDial(t, upstream)
	backend = testTCPAccept(t, upstream)
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		defer src.Close()
		defer dst.Close()
		relayTCPPair(context.Background(), src, dst, &TrafficCounter{}, 0, t.Name(), halfCloseIdle)
	}()
	t.Cleanup(func() {
		src.Close()
		dst.Close()
		select {
		case <-closed:
		case <-time.After(tcpTestTimeout):
			t.Error("pair did not exit on cleanup")
		}
	})
	return client, backend, closed
}

func TestTCPHalfCloseIdleReclaimsSilentPeer(t *testing.T) {
	const idle = 80 * time.Millisecond
	client, backend, done := testTCPPair(t, idle)
	select {
	case <-done:
		t.Fatal("regular full-duplex stream was timed out")
	case <-time.After(2 * idle):
	}
	payload := []byte("still usable")
	tcpTestWrite(t, client, payload)
	tcpTestRead(t, backend, payload)
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	tcpTestEOF(t, backend, "half-close before silent peer expiry")
	// Deliberately keep the other peer open and silent.
	select {
	case <-done:
	case <-time.After(tcpTestTimeout):
		t.Fatal("silent half-closed connection was not reclaimed")
	}
	tcpTestEOF(t, client, "client received EOF after half-close idle expiry")
}

func TestTCPHalfCloseIdleResetsOnResponseBytes(t *testing.T) {
	const idle = 250 * time.Millisecond
	client, backend, done := testTCPPair(t, idle)
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	tcpTestEOF(t, backend, "client FIN before a streamed response")
	payload := []byte("next chunk")
	for i := 0; i < 8; i++ {
		// Total duration exceeds the half-close timeout, gaps do not.
		select {
		case <-done:
			t.Fatal("the relay cut off a progressing half-closed stream")
		case <-time.After(55 * time.Millisecond):
		}
		tcpTestWrite(t, backend, payload)
		tcpTestRead(t, client, payload)
	}
	if err := backend.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	tcpTestEOF(t, client, "streamed response finished")
	select {
	case <-done:
	case <-time.After(tcpTestTimeout):
		t.Fatal("streaming pair did not close")
	}
}

type tcpTestReadFunc func([]byte) (int, error)

func (f tcpTestReadFunc) Read(p []byte) (int, error) { return f(p) }

func TestTCPCountedCopyCancelsLimiterWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var c int64
	ready := make(chan struct{})
	done := make(chan error, 1)
	reads := 0
	reader := tcpTestReadFunc(func(p []byte) (int, error) {
		reads++
		if reads == 1 {
			return len(p), nil
		}
		if reads == 2 {
			close(ready)
			return len(p), nil
		}
		return 0, io.EOF
	})
	go func() { done <- copyCount(ctx, io.Discard, reader, &c, 1, t.Name(), func() {}) }()
	select {
	case <-ready:
	case <-time.After(tcpTestTimeout):
		t.Fatal("did not reach the second rate-limited copy")
	}
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled || atomic.LoadInt64(&c) != CopyBufferSize {
			t.Fatalf("limiter cancellation did not preserve counted bytes: count=%d err=%v", atomic.LoadInt64(&c), err)
		}
	case <-time.After(tcpTestTimeout):
		t.Fatal("limiter wait did not cancel")
	}
}

func TestTCPQuotaClosesPair(t *testing.T) {
	entry, upstream := testTCPListener(t), testTCPListener(t)
	client := testTCPDial(t, entry)
	payload := []byte("consume the last quota")
	tid := t.Name()
	remaining := int64(len(payload))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	taskRemaining.Store(tid, &remaining)
	runningListeners.Store(tid, func() { cancel() })
	t.Cleanup(func() {
		taskRemaining.Delete(tid)
		runningListeners.Delete(tid)
	})
	ctr, done := testTCPTaskWithContext(t, ctx, testTCPAccept(t, entry), upstream, tid)
	backend := testTCPAccept(t, upstream)
	tcpTestWrite(t, client, payload)
	tcpTestRead(t, backend, payload)
	tcpTestEOF(t, backend, "quota reached on a still-open TCP stream")
	tcpTestEOF(t, client, "quota reached on a still-open TCP stream")
	tcpTestDone(t, done, upstream.Addr().String())
	if got := atomic.LoadInt64(&remaining); got != 0 {
		t.Fatalf("unexpected remaining quota: %d", got)
	}
	if got := atomic.LoadInt64(&ctr.Tx); got != int64(len(payload)) {
		t.Fatalf("unexpected transmitted bytes: %d", got)
	}
}

type tcpTestWriteFunc func([]byte) (int, error)

func (f tcpTestWriteFunc) Write(p []byte) (int, error) { return f(p) }

func TestTCPCountedCopyShortWrites(t *testing.T) {
	payload := []byte("count only bytes written")
	var got bytes.Buffer
	var ctr int64
	writer := tcpTestWriteFunc(func(p []byte) (int, error) { return got.Write(p[:min(3, len(p))]) })
	if err := copyCount(context.Background(), writer, bytes.NewReader(payload), &ctr, 0, t.Name(), func() {}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), payload) || ctr != int64(len(payload)) {
		t.Fatalf("short-write output or count mismatch: %q, %d", got.Bytes(), ctr)
	}
	writer = tcpTestWriteFunc(func(p []byte) (int, error) { return 0, nil })
	if err := copyCount(context.Background(), writer, bytes.NewReader(payload), &ctr, 0, t.Name(), func() {}); err != io.ErrShortWrite {
		t.Fatalf("expected io.ErrShortWrite on a zero write, got %v", err)
	}
}
