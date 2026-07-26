package mobile

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
)

// directDialer satisfies netstack.Dialer for direct outbound connections.
type directDialer struct{}

func (d directDialer) DialTCP(ctx context.Context, raddr netip.AddrPort) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", raddr.String())
}

func (d directDialer) DialUDP(ctx context.Context, raddr netip.AddrPort) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "udp", raddr.String())
}

type tunnelPairState struct {
	closed chan struct{}
	once   sync.Once
}

func (p *tunnelPairState) close() {
	p.once.Do(func() {
		close(p.closed)
	})
}

// netstackEndpoint acts as either client-side PacketTunnel or server-side Tunnel.
type netstackEndpoint struct {
	sendCh chan []byte
	recvCh chan []byte
	state  *tunnelPairState
}

func newNetstackTunnelPair() (*netstackEndpoint, *netstackEndpoint) {
	ch1 := make(chan []byte, 512)
	ch2 := make(chan []byte, 512)
	state := &tunnelPairState{closed: make(chan struct{})}

	clientEp := &netstackEndpoint{
		sendCh: ch1,
		recvCh: ch2,
		state:  state,
	}
	serverEp := &netstackEndpoint{
		sendCh: ch2,
		recvCh: ch1,
		state:  state,
	}
	return clientEp, serverEp
}

func (e *netstackEndpoint) ReadPacket(b []byte) (int, error) {
	select {
	case <-e.state.closed:
		return 0, io.EOF
	case data, ok := <-e.recvCh:
		if !ok {
			return 0, io.EOF
		}
		n := copy(b, data)
		return n, nil
	}
}

func (e *netstackEndpoint) WritePacket(b []byte) ([]byte, error) {
	select {
	case <-e.state.closed:
		return nil, io.ErrClosedPipe
	default:
	}
	cp := make([]byte, len(b))
	copy(cp, b)

	select {
	case <-e.state.closed:
		return nil, io.ErrClosedPipe
	case e.sendCh <- cp:
		return nil, nil
	}
}

func (e *netstackEndpoint) Close() error {
	e.state.close()
	return nil
}
