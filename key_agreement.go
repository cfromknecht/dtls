package dtls

import (
	"crypto/elliptic"
	"math/big"
)

type rsaKeyAgreement struct{}

type ecdheKeyAgreement struct {
	version    uint16
	sigType    uint8
	privateKey []byte
	curve      elliptic.Curve
	x, y       *big.Int
}
