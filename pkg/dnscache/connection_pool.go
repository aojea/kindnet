
package dnscache

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// https://www.rfc-editor.org/rfc/rfc7766
// DNS Transport over TCP - Implementation Requirements
const (
	capacity = 3
	timeout  = 50 * time.Millisecond
)

type Pools struct {
	mu   sync.Mutex
	pool map[string]*ConnectionPool
}

func NewPools() *Pools {
	return &Pools{
		pool: map[string]*ConnectionPool{},
	}
}

func (d *Pools) Get(address string) *ConnectionPool {
	d.mu.Lock()
	defer d.mu.Unlock()

	p, ok := d.pool[address]
	if !ok {
		p = NewConnectionPool(address)
	}

	return p
}

func (d *Pools) Delete(address string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	p, ok := d.pool[address]
	if !ok {
		return
	}
	p.Close()
	delete(d.pool, address)
}

// ConnectionPool manages a pool of TCP connections.
type ConnectionPool struct {
	mu          sync.Mutex
	conns       chan *net.TCPConn
	address     string
	activeConns int
}

// NewConnectionPool creates a new connection pool.
func NewConnectionPool(address string) *ConnectionPool {
	pool := &ConnectionPool{
		address: address,
		conns:   make(chan *net.TCPConn, capacity),
	}
	return pool
}

// Get returns a connection from the pool for the given address.
func (p *ConnectionPool) Get() (*net.TCPConn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.activeConns < capacity {
		conn, err := p.newConnection(p.address)
		if err != nil {
			return nil, err
		}
		p.activeConns++
		return conn, nil
	}

	select {
	case conn := <-p.conns:
		return conn, nil
	case <-time.After(timeout):
	}

	return nil, fmt.Errorf("no connections available")
}

// Put returns a connection to the pool for the given address.
func (p *ConnectionPool) Put(conn *net.TCPConn) {
	select {
	case p.conns <- conn:
	case <-time.After(timeout):
		p.mu.Lock()
		defer p.mu.Unlock()
		p.activeConns--
		conn.Close()
	}
}

// newConnection establishes a new TCP connection to the given address.
func (p *ConnectionPool) newConnection(address string) (*net.TCPConn, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		return nil, err
	}

	_ = conn.SetKeepAlive(true)
	_ = conn.SetKeepAlivePeriod(30 * time.Second)

	return conn, nil
}

// Close closes all connections in the pool.
func (p *ConnectionPool) Close() {
	for conn := range p.conns {
		conn.Close()
	}
}
