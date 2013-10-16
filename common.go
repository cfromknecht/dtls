package dtls

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"io"
	"sync"
	"time"
)

const (
	VersionDTLS10 = 0x0301
	VersionDTLS12 = 0x0303
)

const (
	signatureRSA   uint8 = 1
	signatureECDSA uint8 = 3
)

const (
	maxDatagramLength = 1479
	maxPlaintext      = 16384
	maxCiphertext     = 16384 + 2048
	recordHeaderLen   = 13
	recordEpochStart  = 4
	recordSequenceEnd = 12
	maxHandshake      = 65536
)

const (
	compressionNone uint8 = 0
)

type recordType uint8

const (
	recordTypeChangeCipherSpec recordType = 20
	recordTypeAlert            recordType = 21
	recordTypeHandshake        recordType = 22
	recordTypeApplicationData  recordType = 23
)

const (
	typeClientHello        uint8 = 1
	typeServerHello        uint8 = 2
	typeHelloVerifyRequest uint8 = 3
	typeNewSessionTicket   uint8 = 4
	typeCertificate        uint8 = 11
	typeServerKeyExchange  uint8 = 12
	typeCertificateRequest uint8 = 13
	typeServerHelloDone    uint8 = 14
	typeCertificateVerify  uint8 = 15
	typeClientKeyExchange  uint8 = 16
	typeFinished           uint8 = 20
	typeCertificateStatus  uint8 = 22
	typeNextProtocol       uint8 = 67 // Not IANA assigned
)

const (
	minVersion = VersionDTLS10
	maxVersion = VersionDTLS12
)

type ClientAuthType int

const (
	NoClientCert ClientAuthType = iota
	RequestClientCert
	RequireAnyClientCert
	VerifyClientCertIfGiven
	RequireAndVerifyClientCert
)

type record struct {
	contentType    recordType
	major, minor   uint8
	epoch          uint16
	sequenceNumber [6]byte
	payload        []byte
}

type Config struct {
	Rand                     io.Reader
	Time                     func() time.Time
	Certificates             []Certificate
	NameToCertificate        map[string]*Certificate
	RootCAs                  *x509.CertPool
	NextProtos               []string
	ServerName               string
	ClientAuth               ClientAuthType
	ClientCAs                *x509.CertPool
	InsecureSkipVerify       bool
	CipherSuites             []uint16
	PreferServerCipherSuites bool
	SessionTicketsDisabled   bool
	SessionTicketKey         [32]byte
	MinVersion               uint16
	MaxVersion               uint16
	serverInitOnce           sync.Once
}

func (c *Config) serverInit() {
	if c.SessionTicketsDisabled {
		return
	}

	for _, b := range c.SessionTicketKey {
		if b != 0 {
			return
		}
	}

	if _, err := io.ReadFull(c.rand(), c.SessionTicketKey[:]); err != nil {
		c.SessionTicketsDisabled = true
	}
}

func (c *Config) rand() io.Reader {
	r := c.Rand
	if r == nil {
		return rand.Reader
	}
	return r
}

func (c *Config) time() time.Time {
	t := c.Time
	if t == nil {
		t = time.Now
	}
	return t()
}

func (c *Config) cipherSuites() []uint16 {
	s := c.CipherSuites
	if s == nil {
		s = defaultCipherSuites()
	}
	return s
}

func (c *Config) minVersion() uint16 {
	if c == nil || c.MinVersion == 0 {
		return minVersion
	}
	return c.MinVersion
}

func (c *Config) maxVersion() uint16 {
	if c == nil || c.MaxVersion == 0 {
		return maxVersion
	}
	return c.MaxVersion
}

type Certificate struct {
	Certificate [][]byte
	PrivateKey  crypto.PrivateKey
	OCSPStaple  []byte
	Leaf        *x509.Certificate
}

var (
	once                   sync.Once
	varDefaultCipherSuites []uint16
)

func defaultCipherSuites() []uint16 {
	once.Do(initDefaultCipherSuites)
	return varDefaultCipherSuites
}

func initDefaultCipherSuites() {
	varDefaultCipherSuites = make([]uint16, len(cipherSuites))
	for i, suite := range cipherSuites {
		varDefaultCipherSuites[i] = suite.id
	}
}
