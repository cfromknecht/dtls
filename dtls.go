package dtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"net"
	"strings"
)

const (
	Port string = ":8080"
)

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
		config:  config,
	}
	return
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
	if err = c.Handshake(); err != nil {
		conn.Close()
		return
	}
	return
}

func Server(conn net.UDPConn, addr *net.UDPAddr, config *Config) *DTLSConn {
	return &DTLSConn{conn: conn,
		addr:       addr,
		config:     config,
		msgIn:      make(chan []byte, 64),
		nextRecord: make(chan []byte),
	}
}

func Client(conn net.UDPConn, addr *net.UDPAddr, config *Config) *DTLSConn {
	return &DTLSConn{conn: conn,
		addr:       addr,
		config:     config,
		msgIn:      make(chan []byte, 64),
		nextRecord: make(chan []byte),
		isClient:   true,
	}
}

type DTLSMultiplexedConn struct {
	net.UDPConn
	servers map[string]*DTLSConn
	config  *Config
}

func (conn *DTLSMultiplexedConn) Accept() (c *DTLSConn, err error) {
	var b [maxDatagramLength]byte
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

func defaultConfig() *Config {
	return &Config{}
}

// for testing
func DialAndWrite(config *Config) {
	conn, err := Dial("udp", "127.0.0.1"+Port, config)
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
