package main

import (
	"net"
	"log"
	"io"
	"io/ioutil"
	"time"
	"encoding/pem"
	"crypto"
	"crypto/x509"
	"errors"
	"strings"
	"crypto/rsa"
	"crypto/ecdsa"
)

const (
	port string = ":8080"
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

type DTLSMultiplexedConn struct {
	net.UDPConn
	servers map[string]*DTLSConn
	config *Config
}

type DTLSConn struct {
	conn net.UDPConn
	isClient bool
	addr *net.UDPAddr
	config *Config
	msgIn chan []byte
}

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


func main() {
	cert, err := LoadX509KeyPair("certs/server.pem", "certs/server.key")
    if err != nil {
        log.Fatalf("server: loadkeys: %s", err)
    }
    config := Config{Certificates: []Certificate{cert}, InsecureSkipVerify: true}
    
	ln, err := Listen("udp", "127.0.0.1"+port, &config)
	if err != nil {
		return
	}

	ccert, err := LoadX509KeyPair("certs/client.pem", "certs/client.key")
    if err != nil {
        log.Fatalf("server: loadkeys: %s", err)
    }
    cconfig := Config{Certificates: []Certificate{ccert}, InsecureSkipVerify: true}

	go dialAndWrite(&cconfig)
	go dialAndWrite(&cconfig)

	for {
		_, err := ln.Accept()
		if err != nil {
			continue
		}

		// go handle conn
	}
}

func Listen(network, addr string, config *Config) (c *DTLSMultiplexedConn, err error) {
	if config == nil || len(config.Certificates) == 0 {
		err = errors.New("dtls.Listen: no certificates in configuration")
		return
	}
	laddr, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return
	}

	ln, err := net.ListenUDP(network, laddr)
	if err != nil {
		return
	}
	c = &DTLSMultiplexedConn{
		UDPConn: *ln, 
		servers: make(map[string]*DTLSConn),
		config: config,
	}
	return
}

func (conn *DTLSMultiplexedConn) Accept() (c *DTLSConn, err error) {
	var b [maxUDPLength]byte
	n, addr, err := conn.ReadFromUDP(b[0:])
	if err != nil {
		return
	}

	defer func(bb []byte) {
		c.msgIn <- bb
	}(b[0:n])

	if c, ok := conn.servers[addr.String()]; ok {
		return c, nil
	}

	c = Server(conn.UDPConn, addr, conn.config)
	conn.servers[addr.String()] = c
	go c.serve()
	return c, nil
}

func Server(conn net.UDPConn, addr *net.UDPAddr, config *Config) *DTLSConn {
	return &DTLSConn{conn: conn, addr: addr, config: config, msgIn: make(chan []byte, 64)}
}

func Client(conn net.UDPConn, addr *net.UDPAddr, config *Config) *DTLSConn {
	return &DTLSConn{conn: conn, addr: addr, config: config, msgIn: make(chan []byte, 64), isClient: true}
}

func Dial(network, addr string, config *Config) (c *DTLSConn, err error) {
	raddr, err := net.ResolveUDPAddr(network, addr)
	conn, err := net.DialUDP(network, nil, raddr)
	if err != nil {
		return
	}

	colonPos := strings.LastIndex(addr, ":")
	if colonPos == -1 {
		colonPos = len(addr)
	}
	hostname := addr[:colonPos]

	if config == nil {
		config = defaultConfig()
	}

	if config.ServerName == "" {
		cc := *config
		cc.ServerName = hostname
		config = &cc
	}

	c = Client(*conn, raddr, config)
	// c = Client(*conn, raddr)
	// if err = c.Handshake(); err != nil {
	// 	conn.Close()
	// 	return
	// }
	return
}

func defaultConfig() *Config {
	return &Config{}
}

func (c *DTLSConn) Write(b []byte) (n int, err error) {
	n, err = c.conn.Write(b)
	return
}

func (c *DTLSConn) serve() {
	for {
		b := <- c.msgIn
		log.Println("Addr:", c.addr.String(), "\tContents:", string(b))
	}
}

// for testing
func dialAndWrite(config *Config) {
	conn, err := Dial("udp", "127.0.0.1"+port, config)
	if err != nil {
		return
	}
	conn.Write([]byte("hello world"))
}

// same as "tls" implementation
func LoadX509KeyPair(certFile, keyFile string) (cert Certificate, err error) {
	certPEMBlock, err := ioutil.ReadFile(certFile)
	if err != nil {
		return
	}
	keyPEMBlock, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return
	}
	return X509KeyPair(certPEMBlock, keyPEMBlock)
}

// same as "tls" implementation
func X509KeyPair(certPEMBlock, keyPEMBlock []byte) (cert Certificate, err error) {
	var certDERBlock *pem.Block
	for {
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		}
	}

	if len(cert.Certificate) == 0 {
		err = errors.New("crypto/tls: failed to parse certificate PEM data")
		return
	}

	var keyDERBlock *pem.Block
	for {
		keyDERBlock, keyPEMBlock = pem.Decode(keyPEMBlock)
		if keyDERBlock == nil {
			err = errors.New("crypto/tls: failed to parse key PEM data")
			return
		}
		if keyDERBlock.Type == "PRIVATE KEY" || strings.HasSuffix(keyDERBlock.Type, " PRIVATE KEY") {
			break
		}
	}

	cert.PrivateKey, err = parsePrivateKey(keyDERBlock.Bytes)
	if err != nil {
		return
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return
	}

	switch pub := x509Cert.PublicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := cert.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			err = errors.New("crypto/tls: private key type does not match public key type")
			return
		}
		if pub.N.Cmp(priv.N) != 0 {
			err = errors.New("crypto/tls: private key does not match public key")
			return
		}
	case *ecdsa.PublicKey:
		priv, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			err = errors.New("crypto/tls: private key type does not match public key type")
			return

		}
		if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			err = errors.New("crypto/tls: private key does not match public key")
			return
		}
	default:
		err = errors.New("crypto/tls: unknown public key algorithm")
		return
	}

	return
}

// same as "tls" implementation
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("crypto/tls: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("crypto/tls: failed to parse private key")
}