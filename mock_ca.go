package gosdjwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
)

// NewECDSAKeyPair returns a new ECDSA key pair.
func NewECDSAKeyPair(curve elliptic.Curve) (*ecdsa.PublicKey, *ecdsa.PrivateKey, error) {
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	return &privKey.PublicKey, privKey, nil
}

// NewED25519KeyPair returns a new ED25519 key pair.
func NewED25519KeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// NewRSAKeyPair returns a new RSA key pair.
func NewRSAKeyPair(bits int) (*rsa.PublicKey, *rsa.PrivateKey, error) {
	if bits == 0 {
		bits = 2048
	}
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}

	return &privKey.PublicKey, privKey, nil
}
