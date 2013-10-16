package dtls

import (
	"crypto/cipher"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

type DTLSConn struct {
	conn     net.UDPConn
	isClient bool
	msgIn    chan []byte

	handshakeMutex    sync.Mutex
	vers              uint16
	handshakeComplete bool
	addr              *net.UDPAddr
	config            *Config

	connErr

	in, out halfConn

	tmp [16]byte
}

func (c *DTLSConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *DTLSConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *DTLSConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *DTLSConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *DTLSConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

type halfConn struct {
	sync.Mutex
	vers   uint16
	cipher interface{}
	mac    macFunction
	bfree  *block
	epoch  uint16
	seq    [6]byte

	nextCipher interface{}
	nextMac    macFunction
}

func (hc *halfConn) prepareCipherSpec(version uint16, cipher interface{}, mac macFunction) {
	hc.vers = version
	hc.nextCipher = cipher
	hc.nextMac = mac
}

func (hc *halfConn) changeCipherSpec() error {
	if hc.nextCipher == nil {
		return alertInternalError
	}
	hc.cipher = hc.nextCipher
	hc.mac = hc.nextMac
	hc.nextCipher = nil
	hc.nextMac = nil
	for i := range hc.seq {
		hc.seq[i] = 0
	}
	return nil
}

func (hc *halfConn) newBlock() *block {
	b := hc.bfree
	if b == nil {
		return new(block)
	}
	hc.bfree = b.link
	b.link = nil
	b.resize(0)
	return b
}

func (hc *halfConn) freeBlock(b *block) {
	b.link = hc.bfree
	hc.bfree = b
}

func (hc *halfConn) splitBlock(b *block, n int) (*block, *block) {
	if len(b.data) <= n {
		return b, nil
	}
	bb := hc.newBlock()
	bb.resize(len(b.data) - n)
	copy(bb.data, b.data[n:])
	b.data = b.data[0:n]
	return b, bb
}

type block struct {
	data []byte
	off  int
	link *block
}

func (b *block) resize(n int) {
	if n > cap(b.data) {
		b.reserve(n)
	}
	b.data = b.data[0:n]
}

func (b *block) reserve(n int) {
	if cap(b.data) >= n {
		return
	}
	m := cap(b.data)
	if m == 0 {
		m = 1024
	}
	for m < n {
		m *= 2
	}
	data := make([]byte, len(b.data), m)
	copy(data, b.data)
	b.data = data
}

func (b *block) readFromUntil(r net.UDPConn, n int) error {
	if len(b.data) >= n {
		return nil
	}

	b.reserve(n)
	for {
		m, _, err := r.ReadFromUDP(b.data[len(b.data):cap(b.data)])
		b.data = b.data[0 : len(b.data)+m]
		if len(b.data) >= n {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (b *block) Read(p []byte) (n int, err error) {
	n = copy(p, b.data[b.off:])
	b.off += n
	return
}

func (c *DTLSConn) Write(b []byte) (n int, err error) {
	n, err = c.conn.Write(b)
	return
}

func (c *DTLSConn) serve() {
	for {
		b := <-c.msgIn
		log.Println("Addr:", c.addr.String(), "\tContents:", string(b))
	}
}

func (c *DTLSConn) Handshake() (err error) {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()
	if err = c.error(); err != nil {
		return
	}
	if c.handshakeComplete {
		return
	}
	if c.isClient {
		return c.clientHandshake()
	}
	return c.serverHandshake()
}

func (c *DTLSConn) writeRecord(typ recordType, data []byte) (n int, err error) {
	b := c.out.newBlock()
	for len(data) > 0 {
		m := len(data)
		if m > maxDatagramLength {
			m = maxDatagramLength
		}
		explicitIVLen := 0
		explicitIVIsSeq := false

		var cbc cbcMode
		if c.out.vers >= VersionDTLS12 {
			var ok bool
			if cbc, ok = c.out.cipher.(cbcMode); ok {
				explicitIVLen = cbc.BlockSize()
			}
		}
		if explicitIVLen == 0 {
			if _, ok := c.out.cipher.(cipher.AEAD); ok {
				explicitIVLen = 8
				explicitIVIsSeq = true
			}
		}
		b.resize(recordHeaderLen + explicitIVLen + m)
		b.data[0] = byte(typ)
		vers := c.vers
		if vers == 0 {
			// Some TLS servers fail if the record version is
			// greater than TLS 1.0 for the initial ClientHello.
			vers = VersionDTLS10
		}
		b.data[1] = byte(vers >> 8)
		b.data[2] = byte(vers)
		b.data[3] = byte(c.out.epoch >> 8)
		b.data[4] = byte(c.out.epoch)
		copy(b.data[5:11], c.out.seq[:])
		b.data[11] = byte(m >> 8)
		b.data[12] = byte(m)
		if explicitIVLen > 0 {
			explicitIV := b.data[recordHeaderLen : recordHeaderLen+explicitIVLen]
			if explicitIVIsSeq {
				explicitIV[0] = byte(c.out.epoch >> 8)
				explicitIV[1] = byte(c.out.epoch)
				copy(explicitIV[2:], c.out.seq[:])
			} else {
				if _, err = io.ReadFull(c.config.rand(), explicitIV); err != nil {
					break
				}
			}
		}
		copy(b.data[recordHeaderLen+explicitIVLen:], data)
		// c.out.encrypt(b, explicitIVLen)
		_, err = c.conn.Write(b.data)
		log.Println("block written")
		if err != nil {
			break
		}
		n += m
		data = data[m:]
	}
	c.out.freeBlock(b)

	if typ == recordTypeChangeCipherSpec {
		err = c.out.changeCipherSpec()
		if err != nil {
			// Cannot call sendAlert directly,
			// because we already hold c.out.Mutex.
			c.tmp[0] = byte(alertLevelError)
			c.tmp[1] = byte(err.(alert))
			c.writeRecord(recordTypeAlert, c.tmp[0:2])
			return n, c.setError(&net.OpError{Op: "local error", Err: err})
		}
	}
	return
}

func (c *DTLSConn) sendAlertLocked(err alert) error {
	switch err {
	case alertNoRenegotiation, alertCloseNotify:
		c.tmp[0] = byte(alertLevelWarning)
	default:
		c.tmp[0] = byte(alertLevelError)
	}
	c.tmp[1] = byte(err)
	c.writeRecord(recordTypeAlert, c.tmp[0:2])

	if err != alertCloseNotify {
		return c.setError(&net.OpError{Op: "local error", Err: err})
	}
	return nil
}

func (c *DTLSConn) sendAlert(err alert) error {
	c.out.Lock()
	defer c.out.Unlock()
	return c.sendAlertLocked(err)
}

type connErr struct {
	mu    sync.Mutex
	value error
}

func (e *connErr) setError(err error) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.value == nil {
		e.value = err
	}
	return err
}

func (e *connErr) error() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.value
}

type cbcMode interface {
	cipher.BlockMode
	SetIV([]byte)
}
