package dtls

import (
	"io"
	"time"
	"crypto"
	"crypto/x509"
)

const (
	maxUDPLength uint16 = 9216
)

type ClientAuthType int

const (
	NoClientCert ClientAuthType = iota
	RequestClientCert
	RequireAnyClientCert
	VerifyClientCertIfGiven
	RequireAndVerifyClientCert
)

type Config struct {
	Rand io.Reader
	Time func() time.Time
	Certificates []Certificate
	NameToCertificate map[string]*Certificate
	RootCAs *x509.CertPool
	NextProtos []string
	ServerName string
	ClientAuth ClientAuthType
	ClientCAs *x509.CertPool
	InsecureSkipVerify bool
	CipherSuites []uint16
	PreferServerCipherSuites bool
	SessionTicketsDisabled bool
	SessionTicketKey [32]byte
	MinVersion uint16
	MaxVersion uint16
}

type Certificate struct {
	Certificate [][]byte
	PrivateKey  crypto.PrivateKey
	OCSPStaple []byte
	Leaf *x509.Certificate
}
