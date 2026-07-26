package mobile

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"quicdiver/internal/packet"
)

var (
	ErrClosed    = errors.New("mobile: fd source closed")
	ErrInvalidFD = errors.New("mobile: invalid file descriptor")
)

// FDSource implements packet.Source over an open TUN file descriptor.
type FDSource struct {
	file   *os.File
	mtu    int
	mu     sync.Mutex
	closed bool
}

// NewFDSource wraps an open file descriptor into a packet.Source.
func NewFDSource(fd int, mtu int) (*FDSource, error) {
	if fd < 0 {
		return nil, ErrInvalidFD
	}
	if mtu <= 0 {
		mtu = 1500
	}
	f := os.NewFile(uintptr(fd), "tun")
	if f == nil {
		return nil, ErrInvalidFD
	}
	return &FDSource{
		file: f,
		mtu:  mtu,
	}, nil
}

func (s *FDSource) Recv(ctx context.Context) ([]packet.Packet, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrClosed
	}
	file := s.file
	s.mu.Unlock()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		_ = file.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		buf := make([]byte, s.mtu+200)
		n, err := file.Read(buf)
		if err != nil {
			if os.IsTimeout(err) {
				continue
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
		if n == 0 {
			continue
		}
		return []packet.Packet{{
			Data: buf[:n],
			Dir:  packet.Outbound,
		}}, nil
	}
}

func (s *FDSource) Send(pkts []packet.Packet) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	for _, p := range pkts {
		if len(p.Data) == 0 {
			continue
		}
		_, err := s.file.Write(p.Data)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *FDSource) MTU() int {
	return s.mtu
}

func (s *FDSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	_ = s.file.SetReadDeadline(time.Now())
	return s.file.Close()
}

var _ packet.Source = (*FDSource)(nil)
