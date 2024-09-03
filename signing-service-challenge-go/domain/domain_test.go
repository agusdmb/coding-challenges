package domain

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateSecureDataToBeSign(t *testing.T) {
	message := "this is the data"
	lastSignature := "last signature"
	lastSignatureBase64 := base64.StdEncoding.EncodeToString([]byte(lastSignature))
	deviceId, error := uuid.NewRandom()
	require.Nil(t, error)

	t.Run("Initial signature with counter 0", func(t *testing.T) {
		signatureCount := 0

		got := generateSecureDataToBeSign(signatureCount, message, lastSignatureBase64, deviceId)
		deviceIdBase64 := base64.StdEncoding.EncodeToString(deviceId[:])
		expect := fmt.Sprintf("%d_%s_%s", signatureCount, message, deviceIdBase64)
		assert.Equal(t, expect, got)
	})

	t.Run("Subsequent signature with counter > 0", func(t *testing.T) {
		signatureCount := 1

		got := generateSecureDataToBeSign(signatureCount, message, lastSignatureBase64, deviceId)
		expect := fmt.Sprintf("%d_%s_%s", signatureCount, message, lastSignatureBase64)
		assert.Equal(t, expect, got)
	})
}

func TestSignatureServiceSign(t *testing.T) {
	t.Run("Sign data first time", func(t *testing.T) {
		repository := NewFakeRepository()
		signatureService, err := NewSignatureService(testAlgorithms, repository)
		require.Nil(t, err)
		deviceId, err := signatureService.NewSignatureDevice("Dummy", "first device")
		require.Nil(t, err)
		message := "this is the data"
		signature, _, err := signatureService.SignData(deviceId, message)
		assert.Nil(t, err)
		deviceIdBase64 := base64.StdEncoding.EncodeToString(deviceId[:])
		specialString := fmt.Sprintf("%d_%s_%s", 0, message, deviceIdBase64)
		expect := base64.StdEncoding.EncodeToString([]byte(specialString))
		assert.Equal(t, expect, signature)
	})

	t.Run("Sign data multiple times", func(t *testing.T) {
		repository := NewFakeRepository()
		signatureService, err := NewSignatureService(testAlgorithms, repository)
		require.Nil(t, err)
		deviceId, err := signatureService.NewSignatureDevice("Dummy", "first device")
		require.Nil(t, err)
		message := "this is the data"
		signature, _, err := signatureService.SignData(deviceId, message)
		require.Nil(t, err)
		newSignature, _, err := signatureService.SignData(deviceId, message)
		specialString := fmt.Sprintf("%d_%s_%s", 1, message, signature)
		expect := base64.StdEncoding.EncodeToString([]byte(specialString))
		assert.Equal(t, expect, newSignature)
	})
}
