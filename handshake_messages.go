package dtls

import (
	"bytes"
)

type clientHelloMsg struct {
	raw                []byte
	vers               uint16
	random             []byte
	sessionId          []byte
	cookie             []byte
	cipherSuites       []uint16
	compressionMethods []byte
	// extensions to be implemented
}

func (m *clientHelloMsg) equal(i interface{}) bool {
	m1, ok := i.(*clientHelloMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		m.vers == m1.vers &&
		bytes.Equal(m.random, m1.random) &&
		bytes.Equal(m.sessionId, m1.sessionId) &&
		bytes.Equal(m.cookie, m1.cookie) &&
		eqUint16s(m.cipherSuites, m1.cipherSuites) &&
		bytes.Equal(m.compressionMethods, m1.compressionMethods)
}

func (m *clientHelloMsg) marshal() (x []byte) {
	if m.raw != nil {
		return m.raw
	}

	length := 2 + 32 + 1 + len(m.sessionId) + 1 + len(m.cookie) + 2 + 2*len(m.cipherSuites) + 1 + len(m.compressionMethods)
	// no extesions yet

	x = make([]byte, 4+length)
	x[0] = typeClientHello
	x[1] = byte(length >> 16)
	x[2] = byte(length >> 8)
	x[3] = byte(length)
	x[4] = byte(m.vers >> 8)
	x[5] = byte(m.vers)
	copy(x[6:38], m.random)
	x[38] = uint8(len(m.sessionId))
	copy(x[39:39+len(m.sessionId)], m.sessionId)
	c := x[39+len(m.sessionId):]
	c[0] = uint8(len(m.cookie))
	copy(c[1:1+len(m.cookie)], m.cookie)
	y := c[1+len(m.cookie):]
	y[0] = uint8(len(m.cipherSuites) >> 7)
	y[1] = uint8(len(m.cipherSuites) << 1)
	for i, suite := range m.cipherSuites {
		y[2+i*2] = uint8(suite >> 8)
		y[3+i*2] = uint8(suite)
	}
	z := y[2+len(m.cipherSuites)*2:]
	z[0] = uint8(len(m.compressionMethods))
	copy(z[1:], m.compressionMethods)

	// marshal extensions

	m.raw = x
	return
}

func eqUint16s(x, y []uint16) bool {
	if len(x) != len(y) {
		return false
	}
	for i, v := range x {
		if y[i] != v {
			return false
		}
	}
	return true
}
