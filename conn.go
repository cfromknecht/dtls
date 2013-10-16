package dtls

import (
	"bytes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

type DTLSConn struct {
	conn       net.UDPConn
	isClient   bool
	msgIn      chan []byte
	nextRecord chan []byte

	handshakeMutex    sync.Mutex
	vers              uint16
	haveVers          bool
	handshakeComplete bool
	addr              *net.UDPAddr
	config            *Config

	connErr

	in, out  halfConn
	rawInput *block
	input    *block
	hand     bytes.Buffer

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

	inDigestBuf, outDigestBuf []byte
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
	hc.incEpoch()
	hc.resetSeq()
	return nil
}

func (hc *halfConn) incEpoch() {
	hc.epoch++
	if hc.epoch != 0 {
		return
	}
	panic("DTLS: epoch number wraparound")
}

func (hc *halfConn) incSeq() {
	for i := 5; i >= 0; i-- {
		hc.seq[i]++
		if hc.seq[i] != 0 {
			return
		}
	}
	panic("DTLS: sequence number wraparound")
}

func (hc *halfConn) resetSeq() {
	for i := range hc.seq {
		hc.seq[i] = 0
	}
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

func (b *block) readFromUntil(r []byte, n int) error {
	if len(b.data) >= n {
		return nil
	}

	b.reserve(n)
	copy(b.data[len(b.data):cap(b.data)], r)
	return nil
}

func (b *block) Read(p []byte) (n int, err error) {
	n = copy(p, b.data[b.off:])
	b.off += n
	return
}

func roundUp(a, b int) int {
	return a + (b-a%b)%b
}

func removePadding(payload []byte) ([]byte, byte) {
	if len(payload) < 1 {
		return payload, 0
	}

	paddingLen := payload[len(payload)-1]
	t := uint(len(payload)-1) - uint(paddingLen)
	// if len(payload) >= (paddingLen - 1) then the MSB of t is zero
	good := byte(int32(^t) >> 31)

	toCheck := 255 // the maximum possible padding length
	// The length of the padded data is public, so we can use an if here
	if toCheck+1 > len(payload) {
		toCheck = len(payload) - 1
	}

	for i := 0; i < toCheck; i++ {
		t := uint(paddingLen) - uint(i)
		// if i <= paddingLen then the MSB of t is zero
		mask := byte(int32(^t) >> 31)
		b := payload[len(payload)-1-i]
		good &^= mask&paddingLen ^ mask&b
	}

	// We AND together the bits of good and replicate the result across
	// all the bits.
	good &= good << 4
	good &= good << 2
	good &= good << 1
	good = uint8(int8(good) >> 7)

	toRemove := good&paddingLen + 1
	return payload[:len(payload)-int(toRemove)], good
}

func (c *DTLSConn) Write(b []byte) (n int, err error) {
	n, err = c.conn.Write(b)
	return
}

func (c *DTLSConn) serve() {
	for {
		b := <-c.msgIn
		log.Println("Addr:", c.addr.String())
		log.Println("\tSeq:", uint64(b[5])<<40|uint64(b[6])<<32|uint64(b[7])<<24|uint64(b[8])<<16|uint64(b[9])<<8|uint64(b[10]))
		if len(b) >= 13 {
			log.Println("\tLength:", uint16(b[11])<<8|uint16(b[12]))
		}
		log.Println("\tContents:", string(b))
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

func padToBlockSize(payload []byte, blockSize int) (prefix, finalBlock []byte) {
	overrun := len(payload) % blockSize
	paddingLen := blockSize - overrun
	prefix = payload[:len(payload)-overrun]
	finalBlock = make([]byte, blockSize)
	copy(finalBlock, payload[len(payload)-overrun:])
	for i := overrun; i < blockSize; i++ {
		finalBlock[i] = byte(paddingLen - 1)
	}
	return
}

func (hc *halfConn) decrypt(b *block) (ok bool, prefixLen int, alertValue alert) {
	// pull out payload
	payload := b.data[recordHeaderLen:]

	macSize := 0
	if hc.mac != nil {
		macSize = hc.mac.Size()
	}

	paddingGood := byte(255)
	explicitIVLen := 0

	// decrypt
	if hc.cipher != nil {
		switch c := hc.cipher.(type) {
		case cipher.AEAD:
			explicitIVLen = 8
			if len(payload) < explicitIVLen {
				return false, 0, alertBadRecordMAC
			}
			nonce := payload[:8]
			payload = payload[8:]

			var additionalData [13]byte
			additionalData[0] = byte(hc.epoch >> 8)
			additionalData[1] = byte(hc.epoch)
			copy(additionalData[2:], hc.seq[:])
			copy(additionalData[8:], b.data[:3])
			n := len(payload) - c.Overhead()
			additionalData[11] = byte(n >> 8)
			additionalData[12] = byte(n)
			var err error
			payload, err = c.Open(payload[:0], nonce, payload, additionalData[:])
			if err != nil {
				return false, 0, alertBadRecordMAC
			}
			b.resize(recordHeaderLen + explicitIVLen + len(payload))
		case cbcMode:
			blockSize := c.BlockSize()
			if hc.vers >= VersionDTLS12 {
				explicitIVLen = blockSize
			}

			if len(payload)%blockSize != 0 || len(payload) < roundUp(explicitIVLen+macSize+1, blockSize) {
				return false, 0, alertBadRecordMAC
			}

			if explicitIVLen > 0 {
				c.SetIV(payload[:explicitIVLen])
				payload = payload[explicitIVLen:]
			}
			c.CryptBlocks(payload, payload)
			payload, paddingGood = removePadding(payload)
			b.resize(recordHeaderLen + explicitIVLen + len(payload))

			// note that we still have a timing side-channel in the
			// MAC check, below. An attacker can align the record
			// so that a correct padding will cause one less hash
			// block to be calculated. Then they can iteratively
			// decrypt a record by breaking each byte. See
			// "Password Interception in a SSL/TLS Channel", Brice
			// Canvel et al.
			//
			// However, our behavior matches OpenSSL, so we leak
			// only as much as they do.
		default:
			panic("unknown cipher type")
		}
	}

	// check, strip mac
	if hc.mac != nil {
		if len(payload) < macSize {
			return false, 0, alertBadRecordMAC
		}

		// strip mac off payload, b.data
		n := len(payload) - macSize
		b.data[11] = byte(n >> 8)
		b.data[12] = byte(n)
		b.resize(recordHeaderLen + explicitIVLen + n)
		remoteMAC := payload[n:]
		localMAC := hc.mac.MAC(
			hc.inDigestBuf,
			b.data[recordEpochStart:recordSequenceEnd],
			append(b.data[:recordEpochStart], b.data[recordSequenceEnd:recordHeaderLen]...),
			payload[:n],
		)

		if subtle.ConstantTimeCompare(localMAC, remoteMAC) != 1 || paddingGood != 255 {
			return false, 0, alertBadRecordMAC
		}
		hc.inDigestBuf = localMAC
	}
	hc.incSeq()

	return true, recordHeaderLen + explicitIVLen, 0
}

func (hc *halfConn) encrypt(b *block, explicitIVLen int) (bool, alert) {
	// mac
	if hc.mac != nil {
		var epochSeq [8]byte
		epochSeq[0] = byte(hc.epoch >> 8)
		epochSeq[1] = byte(hc.epoch)
		copy(epochSeq[2:], hc.seq[:])
		mac := hc.mac.MAC(
			hc.outDigestBuf,
			epochSeq[:],
			append(b.data[:recordEpochStart], b.data[recordSequenceEnd:recordHeaderLen]...),
			b.data[recordHeaderLen+explicitIVLen:],
		)

		n := len(b.data)
		b.resize(n + len(mac))
		copy(b.data[n:], mac)
		hc.outDigestBuf = mac
	}

	payload := b.data[recordHeaderLen:]

	// encrypt
	if hc.cipher != nil {
		switch c := hc.cipher.(type) {
		case cipher.AEAD:
			payloadLen := len(b.data) - recordHeaderLen - explicitIVLen
			b.resize(len(b.data) + c.Overhead())
			nonce := b.data[recordHeaderLen : recordHeaderLen+explicitIVLen]
			payload := b.data[recordHeaderLen+explicitIVLen:]
			payload = payload[:payloadLen]

			var additionalData [13]byte
			additionalData[0] = byte(hc.epoch >> 8)
			additionalData[1] = byte(hc.epoch)
			copy(additionalData[2:], hc.seq[:])
			copy(additionalData[8:], b.data[:3])
			additionalData[11] = byte(payloadLen >> 8)
			additionalData[12] = byte(payloadLen)

			c.Seal(payload[:0], nonce, payload, additionalData[:])
		case cbcMode:
			blockSize := c.BlockSize()
			if explicitIVLen > 0 {
				c.SetIV(payload[:explicitIVLen])
				payload = payload[explicitIVLen:]
			}
			prefix, finalBlock := padToBlockSize(payload, blockSize)
			b.resize(recordHeaderLen + explicitIVLen + len(prefix) + len(finalBlock))
			c.CryptBlocks(b.data[recordHeaderLen+explicitIVLen:], prefix)
			c.CryptBlocks(b.data[recordHeaderLen+explicitIVLen+len(prefix):], finalBlock)
		default:
			panic("unknown cipher type")
		}
	}

	log.Println("ciphertextLen:", len(b.data))

	// update length to include MAC and any block padding needed.
	n := len(b.data) - recordHeaderLen
	b.data[11] = byte(n >> 8)
	b.data[12] = byte(n)
	hc.incSeq()

	return true, 0
}

func (c *DTLSConn) readRecord(want recordType) error {
	switch want {
	default:
		return c.sendAlert(alertInternalError)
	case recordTypeHandshake, recordTypeChangeCipherSpec:
		if c.handshakeComplete {
			return c.sendAlert(alertInternalError)
		}
	case recordTypeApplicationData:
		if !c.handshakeComplete {
			return c.sendAlert(alertInternalError)
		}
	}

Again:
	if c.rawInput == nil {
		c.rawInput = c.in.newBlock()
	}
	b := c.rawInput

	rec := <-c.nextRecord

	b.readFromUntil(rec, recordHeaderLen)
	// if err := b.readFromUntil(data, recordHeaderLen); err != nil {
	// 	if e, ok := err.(net.Error); !ok || !e.Temporary() {
	// 		c.setError(err)
	// 	}
	// 	return err
	// }
	typ := recordType(b.data[0])

	// No valid TLS record has a type of 0x80, however SSLv2 handshakes
	// start with a uint16 length where the MSB is set and the first record
	// is always < 256 bytes long. Therefore typ == 0x80 strongly suggests
	// an SSLv2 client.
	if want == recordTypeHandshake && typ == 0x80 {
		c.sendAlert(alertProtocolVersion)
		return errors.New("tls: unsupported SSLv2 handshake received")
	}

	vers := uint16(b.data[1])<<8 | uint16(b.data[2])
	n := int(b.data[11])<<8 | int(b.data[12])
	if c.haveVers && vers != c.vers {
		return c.sendAlert(alertProtocolVersion)
	}
	if n > maxCiphertext {
		return c.sendAlert(alertRecordOverflow)
	}
	if !c.haveVers {
		// First message, be extra suspicious:
		// this might not be a TLS client.
		// Bail out before reading a full 'body', if possible.
		// The current max version is 3.1.
		// If the version is >= 16.0, it's probably not real.
		// Similarly, a clientHello message encodes in
		// well under a kilobyte.  If the length is >= 12 kB,
		// it's probably not real.
		if (typ != recordTypeAlert && typ != want) || vers >= 0x1000 || n >= 0x3000 {
			return c.sendAlert(alertUnexpectedMessage)
		}
	}

	b.readFromUntil(rec, recordHeaderLen+n)
	// if err := b.readFromUntil(c.conn, recordHeaderLen+n); err != nil {
	// 	if err == io.EOF {
	// 		err = io.ErrUnexpectedEOF
	// 	}
	// 	if e, ok := err.(net.Error); !ok || !e.Temporary() {
	// 		c.setError(err)
	// 	}
	// 	return err
	// }

	// Process message.
	b, c.rawInput = c.in.splitBlock(b, recordHeaderLen+n)
	ok, off, err := c.in.decrypt(b)
	if !ok {
		return c.sendAlert(err)
	}
	b.off = off
	data := b.data[b.off:]
	if len(data) > maxPlaintext {
		c.sendAlert(alertRecordOverflow)
		c.in.freeBlock(b)
		return c.error()
	}

	switch typ {
	default:
		c.sendAlert(alertUnexpectedMessage)

	case recordTypeAlert:
		if len(data) != 2 {
			c.sendAlert(alertUnexpectedMessage)
			break
		}
		if alert(data[1]) == alertCloseNotify {
			c.setError(io.EOF)
			break
		}
		switch data[0] {
		case byte(alertLevelWarning):
			// drop on the floor
			c.in.freeBlock(b)
			goto Again
		case byte(alertLevelError):
			c.setError(&net.OpError{Op: "remote error", Err: alert(data[1])})
		default:
			c.sendAlert(alertUnexpectedMessage)
		}

	case recordTypeChangeCipherSpec:
		if typ != want || len(data) != 1 || data[0] != 1 {
			c.sendAlert(alertUnexpectedMessage)
			break
		}
		err := c.in.changeCipherSpec()
		if err != nil {
			c.sendAlert(err.(alert))
		}

	case recordTypeApplicationData:
		if typ != want {
			c.sendAlert(alertUnexpectedMessage)
			break
		}
		c.input = b
		b = nil

	case recordTypeHandshake:
		// TODO(rsc): Should at least pick off connection close.
		if typ != want {
			return c.sendAlert(alertNoRenegotiation)
		}
		c.hand.Write(data)
	}

	if b != nil {
		c.in.freeBlock(b)
	}
	return c.error()
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
		c.out.encrypt(b, explicitIVLen)
		_, err = c.conn.Write(b.data)
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
