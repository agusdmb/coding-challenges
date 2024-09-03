package domain

import "github.com/google/uuid"

type SignatureDevice struct {
	id                  uuid.UUID
	algorithm           string
	keyPair             KeyPair
	label               string
	signatureCounter    int
	lastSignatureBase64 string
}

type StoredDevice struct {
	Id                  uuid.UUID
	Algorithm           string
	Label               string
	SignatureCounter    int
	LastSignatureBase64 string
	PrivateKeyBytes     []byte
	PublicKeyBytes      []byte
}

type DeviceInfo struct {
	ID        uuid.UUID
	Label     string
	Algorithm string
	Counter   int
}
