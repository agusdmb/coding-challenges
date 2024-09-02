package crypto

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/fiskaly/coding-challenges/signing-service-challenge/domain"
)

// RSAKeyPair is a DTO that holds RSA private and public keys.
type RSAKeyPair struct {
	Public  *rsa.PublicKey
	Private *rsa.PrivateKey
}

// RSAMarshaler can encode and decode an RSA key pair.
type RSAMarshaler struct{}

// NewRSAMarshaler creates a new RSAMarshaler.
func NewRSAMarshaler() RSAMarshaler {
	return RSAMarshaler{}
}

// Marshal takes an RSAKeyPair and encodes it to be written on disk.
// It returns the public and the private key as a byte slice.
func (m *RSAMarshaler) Marshal(keyPair RSAKeyPair) ([]byte, []byte, error) {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(keyPair.Private)
	publicKeyBytes := x509.MarshalPKCS1PublicKey(keyPair.Public)

	encodedPrivate := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA_PRIVATE_KEY",
		Bytes: privateKeyBytes,
	})

	encodePublic := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA_PUBLIC_KEY",
		Bytes: publicKeyBytes,
	})

	return encodePublic, encodedPrivate, nil
}

// Unmarshal takes an encoded RSA private key and transforms it into a rsa.PrivateKey.
func (m *RSAMarshaler) Unmarshal(privateKeyBytes []byte) (*RSAKeyPair, error) {
	block, _ := pem.Decode(privateKeyBytes)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &RSAKeyPair{
		Private: privateKey,
		Public:  &privateKey.PublicKey,
	}, nil
}

type RSAAlgorithm struct{}

func (d RSAAlgorithm) CreateKeyPair() (domain.KeyPair, error) {
	rsaGenerator := RSAGenerator{}
	keyPair, err := rsaGenerator.Generate()
	return *keyPair, err
}

func (d RSAAlgorithm) SignData(data string, keyPair domain.KeyPair) ([]byte, error) {
	rsaKeyPair, ok := keyPair.(RSAKeyPair)
	if !ok {
		return nil, errors.New("Wrong key pair type")
	}
	hashedMessage := sha256.Sum256([]byte(data))
	signature, err := rsa.SignPKCS1v15(nil, rsaKeyPair.Private, crypto.SHA256, hashedMessage[:])
	if err != nil {
		return nil, fmt.Errorf("Error signing message: %w", err)
	}
	return signature, nil
}
