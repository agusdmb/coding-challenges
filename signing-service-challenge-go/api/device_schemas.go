package api

import (
	"github.com/google/uuid"
)

type CreateSignatureDeviceSchema struct {
	Algorithm string `json:"algorithm"`
	Label     string `json:"label"`
}

type CreateSignatureDeviceResponse struct {
	ID uuid.UUID `json:"id"`
}

type SignTransactionSchema struct {
	DeviceID uuid.UUID `json:"deviceId"`
	Data     string    `json:"data"`
}

type SignTransactionResponse struct {
	Signature  string `json:"signature"`
	SignedData string `json:"signed_data"`
}
