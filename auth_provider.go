package secretd

import (
	"encoding/base64"

	"github.com/flynn/noise"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/curve25519"
)

// StaticKeyAuthProvider implements secretd static key authentication
type StaticKeyAuthProvider struct {
	staticPrivateKey [32]byte
	staticPublicKey  [32]byte
}

// newStaticKeyAuthProvider creates a new static key auth provider with the given base64-formated
// local static private key.
func NewStaticKeyAuthProvider(staticPrivateKey string) (*StaticKeyAuthProvider, error) {
	privateKeySlice, err := base64.StdEncoding.DecodeString(staticPrivateKey)
	if err != nil {
		log.Error("cannot decode static private key")
		return nil, err
	}
	if len(privateKeySlice) != 32 {
		return nil, errors.New("invalid private key length")
	}
	var privateKey, publicKey [32]byte
	copy(privateKey[:], privateKeySlice[:32])

	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return &StaticKeyAuthProvider{
		staticPrivateKey: privateKey,
		staticPublicKey:  publicKey,
	}, nil
}

// Name returns the name of the AuthProvider
func (p *StaticKeyAuthProvider) Name() string {
	return "static_key"
}

// AuthParams returns the authentication parameters
func (p *StaticKeyAuthProvider) AuthParams() interface{} {
	return nil
}

// LocalStaticKeyPair returns local
func (p *StaticKeyAuthProvider) LocalStaticKeypair() noise.DHKey {
	return noise.DHKey{
		Private: p.staticPrivateKey[:],
		Public:  p.staticPublicKey[:],
	}
}
