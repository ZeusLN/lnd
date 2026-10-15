//go:build mobile
// +build mobile

package lndmobile

import (
	"context"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// testPairingPhrase only needs to split into ten words; unknown words map to
// index zero, which is enough to derive a mailbox session ID.
const testPairingPhrase = "one two three four five six seven eight nine ten"

type noopCallback struct{}

func (noopCallback) SendResult(string) {}

// dialCounter is a mailbox stand-in that accepts TCP connections and closes
// them straight away. The client can never complete a handshake against it,
// so every accepted connection is one more redial attempt.
type dialCounter struct {
	ln    net.Listener
	count atomic.Int64
}

func newDialCounter(t *testing.T) *dialCounter {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	d := &dialCounter{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			d.count.Add(1)
			conn.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })

	return d
}

func (d *dialCounter) addr() string {
	return d.ln.Addr().String()
}

// requireRedialing waits until the client has dialed more than once, which
// shows it is retrying on its own rather than making a single attempt.
func (d *dialCounter) requireRedialing(t *testing.T) {
	t.Helper()

	start := d.count.Load()
	require.Eventually(t, func() bool {
		return d.count.Load() >= start+2
	}, 30*time.Second, 50*time.Millisecond, "client never redialed")
}

// requireStopped checks that no new dial attempts arrive once the client has
// been told to stop.
func (d *dialCounter) requireStopped(t *testing.T) {
	t.Helper()

	// let an attempt already in flight land
	time.Sleep(time.Second)
	settled := d.count.Load()
	time.Sleep(8 * time.Second)
	require.Equal(t, settled, d.count.Load(),
		"client kept dialing after it was stopped")
}

func initTestClient(t *testing.T, nameSpace string) {
	t.Helper()

	require.NoError(t, InitLNC(nameSpace, "info"))
	require.NoError(t, RegisterLocalPrivCreateCallback(
		nameSpace, noopCallback{},
	))
	require.NoError(t, RegisterRemoteKeyReceiveCallback(
		nameSpace, noopCallback{},
	))
	require.NoError(t, RegisterAuthDataCallback(nameSpace, noopCallback{}))
}

func connectTestClient(t *testing.T, nameSpace, addr string) {
	t.Helper()

	require.NoError(t, ConnectServer(
		nameSpace, addr, false, testPairingPhrase, "", "",
	))
}

// TestDisconnectStopsDialInProgress checks that Disconnect stops a dial that
// has not connected yet. It used to be a no-op until the dial connected, so
// the dial kept retrying in the background and competed with the next one
// for the same mailbox session.
func TestDisconnectStopsDialInProgress(t *testing.T) {
	mailbox := newDialCounter(t)
	initTestClient(t, "disconnect-dialing")

	connectTestClient(t, "disconnect-dialing", mailbox.addr())
	mailbox.requireRedialing(t)

	require.NoError(t, Disconnect("disconnect-dialing"))
	mailbox.requireStopped(t)

	connected, err := IsConnected("disconnect-dialing")
	require.NoError(t, err)
	require.False(t, connected)
}

// TestInitLNCStopsDialInProgress checks that re-initializing a namespace stops
// the dial on the client it replaces instead of orphaning it.
func TestInitLNCStopsDialInProgress(t *testing.T) {
	mailbox := newDialCounter(t)
	initTestClient(t, "reinit-dialing")

	connectTestClient(t, "reinit-dialing", mailbox.addr())
	mailbox.requireRedialing(t)

	require.NoError(t, InitLNC("reinit-dialing", "info"))
	mailbox.requireStopped(t)
}

// TestConnectServerStopsPreviousDial checks that a second ConnectServer on the
// same client replaces the dial in progress rather than running alongside it.
func TestConnectServerStopsPreviousDial(t *testing.T) {
	first := newDialCounter(t)
	second := newDialCounter(t)
	initTestClient(t, "redial")

	connectTestClient(t, "redial", first.addr())
	first.requireRedialing(t)

	connectTestClient(t, "redial", second.addr())
	second.requireRedialing(t)
	first.requireStopped(t)

	require.NoError(t, Disconnect("redial"))
}

// TestConnectServerAfterDisconnect checks that a stopped client can dial
// again.
func TestConnectServerAfterDisconnect(t *testing.T) {
	mailbox := newDialCounter(t)
	initTestClient(t, "reconnect")

	connectTestClient(t, "reconnect", mailbox.addr())
	mailbox.requireRedialing(t)
	require.NoError(t, Disconnect("reconnect"))
	mailbox.requireStopped(t)

	connectTestClient(t, "reconnect", mailbox.addr())
	mailbox.requireRedialing(t)

	require.NoError(t, Disconnect("reconnect"))
}

// resultCallback counts the results InvokeRPC sends back.
type resultCallback struct {
	wg *sync.WaitGroup
}

func (r resultCallback) SendResult(string) {
	r.wg.Done()
}

// testConn returns a client connection that never dials. The fake RPCs below
// only compare it, so it never needs to reach a server.
func testConn(t *testing.T) *grpc.ClientConn {
	t.Helper()

	conn, err := grpc.NewClient(
		"passthrough:///unused",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	return conn
}

// setTestConn marks the client as connected on conn without a mailbox.
func setTestConn(t *testing.T, nameSpace string, conn *grpc.ClientConn) {
	t.Helper()

	mc, err := getClient(nameSpace)
	require.NoError(t, err)

	mc.mutex.Lock()
	mc.lndConn = conn
	mc.mutex.Unlock()
}

// TestInvokeRPCDoesNotLeakGoroutines checks that a call's goroutine ends once
// the RPC has returned its result. It used to wait on a context that was
// never cancelled, so every call left a goroutine behind.
func TestInvokeRPCDoesNotLeakGoroutines(t *testing.T) {
	const calls = 50

	initTestClient(t, "invoke-leak")
	setTestConn(t, "invoke-leak", testConn(t))

	registry["test.Leak.Unary"] = func(_ context.Context,
		_ *grpc.ClientConn, _ string, callback func(string, error)) {

		callback("{}", nil)
	}
	t.Cleanup(func() { delete(registry, "test.Leak.Unary") })

	before := runtime.NumGoroutine()

	var wg sync.WaitGroup
	wg.Add(calls)
	for i := 0; i < calls; i++ {
		require.NoError(t, InvokeRPC(
			"invoke-leak", "test.Leak.Unary", "{}",
			resultCallback{wg: &wg},
		))
	}
	wg.Wait()

	require.Eventually(t, func() bool {
		return runtime.NumGoroutine() < before+calls/2
	}, 5*time.Second, 10*time.Millisecond,
		"InvokeRPC left a goroutine behind per call")
}

// TestInvokeRPCKeepsConnAcrossDisconnect checks that a call uses the
// connection that was ready when InvokeRPC accepted it, even if Disconnect
// runs before the call's goroutine starts. It used to read mc.lndConn from
// the goroutine without the mutex and could get nil.
func TestInvokeRPCKeepsConnAcrossDisconnect(t *testing.T) {
	const calls = 200

	initTestClient(t, "invoke-disconnect")
	conn := testConn(t)

	var nilConns atomic.Int64
	registry["test.Disconnect.Unary"] = func(_ context.Context,
		c *grpc.ClientConn, _ string, callback func(string, error)) {

		if c == nil {
			nilConns.Add(1)
		}
		callback("{}", nil)
	}
	t.Cleanup(func() { delete(registry, "test.Disconnect.Unary") })

	var wg sync.WaitGroup
	wg.Add(calls)
	for i := 0; i < calls; i++ {
		setTestConn(t, "invoke-disconnect", conn)
		require.NoError(t, InvokeRPC(
			"invoke-disconnect", "test.Disconnect.Unary", "{}",
			resultCallback{wg: &wg},
		))

		// Clear the connection the way Disconnect does, without
		// closing the shared test connection.
		setTestConn(t, "invoke-disconnect", nil)
	}
	wg.Wait()

	require.Zero(t, nilConns.Load(), "a call ran on a nil connection")
}
