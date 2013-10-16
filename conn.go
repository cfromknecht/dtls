package dtls

import (
	"net"
)

type DTLSConn struct {
	conn net.UDPConn
	isClient bool
	addr *net.UDPAddr
	config *Config
	msgIn chan []byte
}