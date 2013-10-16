package dtls

import (
	"io"
)

func (c *DTLSConn) clientHandshake() (err error) {
	if c.config == nil {
		c.config = defaultConfig()
	}

	// Client Hello

	hello := &clientHelloMsg{
		vers:               c.config.maxVersion(),
		random:             make([]byte, 32),
		compressionMethods: []uint8{compressionNone},
	}

	possibleCipherSuites := c.config.cipherSuites()
	hello.cipherSuites = make([]uint16, 0, len(possibleCipherSuites))

NextCipherSuite:
	for _, suiteId := range possibleCipherSuites {
		for _, suite := range cipherSuites {
			if suite.id != suiteId {
				continue
			}
			// Don't advertise TLS 1.2-only cipher suites unless
			// we're attempting TLS 1.2.
			if hello.vers < VersionDTLS12 && suite.flags&suiteTLS12 != 0 {
				continue
			}
			hello.cipherSuites = append(hello.cipherSuites, suiteId)
			continue NextCipherSuite
		}
	}

	t := uint32(c.config.time().Unix())
	hello.random[0] = byte(t >> 24)
	hello.random[1] = byte(t >> 16)
	hello.random[2] = byte(t >> 8)
	hello.random[3] = byte(t)
	_, err = io.ReadFull(c.config.rand(), hello.random[4:])
	if err != nil {
		c.sendAlert(alertInternalError)
		return
	}
	c.writeRecord(recordTypeHandshake, hello.marshal())

	return
}

func (c *DTLSConn) serverHandshake() (err error) {
	return
}
