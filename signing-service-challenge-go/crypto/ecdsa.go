package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/fiskaly/coding-challenges/signing-service-challenge/domain"
)

// ECCKeyPair is a DTO that holds ECC private and public keys.
type ECCKeyPair struct {
	Public  *ecdsa.PublicKey
	Private *ecdsa.PrivateKey
}

type ECCAlgorithm struct{}

func (d ECCAlgorithm) CreateKeyPair() (domain.KeyPair, error) {
	// Security has been ignored for the sake of simplicity.
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return &ECCKeyPair{
		Public:  &key.PublicKey,
		Private: key,
	}, nil
}

func (d ECCAlgorithm) SignData(data string, keyPair domain.KeyPair) ([]byte, error) {
	eccKeyPair, ok := keyPair.(*ECCKeyPair)
	if !ok {
		return nil, errors.New("ECC Wrong key pair type")
	}

	hash := sha256.New()
	hash.Write([]byte(data))
	hashedMessage := hash.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, eccKeyPair.Private, hashedMessage)
	if err != nil {
		return nil, fmt.Errorf("ECC Error signing data: %w", err)
	}

	signature := append(r.Bytes(), s.Bytes()...)

	return signature, nil
}

// Encode takes an ECCKeyPair and encodes it to be written on disk.
// It returns the public and the private key as a byte slice.
func (d ECCAlgorithm) Marshal(keyPair domain.KeyPair) ([]byte, []byte, error) {
	eccKeyPair, ok := keyPair.(*ECCKeyPair)
	if !ok {
		return nil, nil, errors.New("Wrong key pair type")
	}
	privateKeyBytes, err := x509.MarshalECPrivateKey(eccKeyPair.Private)
	if err != nil {
		return nil, nil, fmt.Errorf("ECC could not marshal private key: %w", err)
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(eccKeyPair.Public)
	if err != nil {
		return nil, nil, fmt.Errorf("ECC could not marshal public key: %w", err)
	}

	encodedPrivate := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE_KEY",
		Bytes: privateKeyBytes,
	})

	encodedPublic := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC_KEY",
		Bytes: publicKeyBytes,
	})

	return encodedPublic, encodedPrivate, nil
}

// Decode assembles an ECCKeyPair from an encoded private key.
func (d ECCAlgorithm) Unmarshal(privateKeyBytes []byte) (domain.KeyPair, error) {
	block, _ := pem.Decode(privateKeyBytes)
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ECC couldn't parse private key: %w", err)
	}

	return &ECCKeyPair{
		Private: privateKey,
		Public:  &privateKey.PublicKey,
	}, nil
}
