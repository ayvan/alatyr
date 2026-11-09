package relay

import (
	"os"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// memTun is an in-process TUN device: nothing is created in the OS.
// Packets the AWG device decrypts are passed to onPacket; packets queued via
// Deliver are handed to the AWG device for encryption.
type memTun struct {
	name     string
	mtu      int
	queue    chan []byte
	events   chan tun.Event
	closed   chan struct{}
	wake     chan struct{}
	once     sync.Once
	onPacket func(pkt []byte)
}

func newMemTun(name string, mtu int, onPacket func([]byte)) *memTun {
	t := &memTun{
		name:     name,
		mtu:      mtu,
		queue:    make(chan []byte, 2048),
		events:   make(chan tun.Event, 4),
		closed:   make(chan struct{}),
		wake:     make(chan struct{}, 1),
		onPacket: onPacket,
	}
	t.events <- tun.EventUp
	return t
}

// Deliver queues a packet for the AWG device; it is dropped when the queue is
// full, like a congested link would.
func (t *memTun) Deliver(pkt []byte) {
	select {
	case t.queue <- pkt:
	case <-t.closed:
	default:
	}
}

// Wake makes a pending (or the next) Read return without packets.
//
// amneziawg-go computes the S4 transport padding offset before blocking in
// Read, and its reader goroutine starts in NewDevice, i.e. before the config
// is applied. Without a wake-up the first packet in each direction would be
// sent with zero padding and dropped by the peer as "unknown type".
func (t *memTun) Wake() {
	select {
	case t.wake <- struct{}{}:
	default:
	}
}

func (t *memTun) File() *os.File { return nil }

func (t *memTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	// Any error other than on close makes the AWG device shut down, so
	// oversized packets are silently dropped instead.
	n := 0
	for n == 0 {
		select {
		case pkt := <-t.queue:
			if len(pkt) <= len(bufs[0])-offset {
				sizes[0] = copy(bufs[0][offset:], pkt)
				n = 1
			}
		case <-t.wake:
			return 0, nil
		case <-t.closed:
			return 0, os.ErrClosed
		}
	}
	for n < len(bufs) {
		select {
		case pkt := <-t.queue:
			if len(pkt) <= len(bufs[n])-offset {
				sizes[n] = copy(bufs[n][offset:], pkt)
				n++
			}
		default:
			return n, nil
		}
	}
	return n, nil
}

func (t *memTun) Write(bufs [][]byte, offset int) (int, error) {
	select {
	case <-t.closed:
		return 0, os.ErrClosed
	default:
	}
	for _, b := range bufs {
		if len(b) <= offset {
			continue
		}
		pkt := make([]byte, len(b)-offset)
		copy(pkt, b[offset:])
		t.onPacket(pkt)
	}
	return len(bufs), nil
}

func (t *memTun) MTU() (int, error)        { return t.mtu, nil }
func (t *memTun) Name() (string, error)    { return t.name, nil }
func (t *memTun) Events() <-chan tun.Event { return t.events }
func (t *memTun) BatchSize() int           { return 64 }

func (t *memTun) Close() error {
	t.once.Do(func() {
		close(t.closed)
		close(t.events)
	})
	return nil
}
