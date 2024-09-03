package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarshalAndUnmarshalDevice(t *testing.T) {
	repository := NewFakeRepository()
	signatureService, err := NewSignatureService(testAlgorithms, repository)
	require.Nil(t, err)
	deviceId, err := signatureService.NewSignatureDevice("Dummy", "first device")
	require.Nil(t, err)
	device, err := signatureService.getDevice(deviceId)
	require.Nil(t, err)
	marshalDevice, err := signatureService.marshalDevice(device)
	assert.Nil(t, err)
	unmarshalDevice, err := signatureService.unmarshalDevice(marshalDevice)
	assert.Nil(t, err)
	assert.Equal(t, device, unmarshalDevice)
}

func TestNewSignatureService(t *testing.T) {
	t.Run("Empty algorithms", func(t *testing.T) {
		emptyAlgorithms := make(map[string]Algorithm[KeyPair])
		repository := NewFakeRepository()
		signatureService, err := NewSignatureService(emptyAlgorithms, repository)
		assert.Nil(t, signatureService)
		assert.NotNil(t, err)
	})

	t.Run("With algorithms", func(t *testing.T) {
		repository := NewFakeRepository()
		signatureService, err := NewSignatureService(testAlgorithms, repository)
		assert.Nil(t, err)
		assert.NotNil(t, signatureService)
	})
}

func TestNewSignatureDevice(t *testing.T) {
	t.Run("With inexisting algorithm", func(t *testing.T) {
		repository := NewFakeRepository()
		signatureService, err := NewSignatureService(testAlgorithms, repository)
		require.Nil(t, err)
		_, err = signatureService.NewSignatureDevice("RSA", "first device")
		assert.EqualError(t, err, "algorithm RSA not in algorithms")
	})

	t.Run("With correct algorithm", func(t *testing.T) {
		repository := NewFakeRepository()
		signatureService, err := NewSignatureService(testAlgorithms, repository)
		require.Nil(t, err)
		deviceId, err := signatureService.NewSignatureDevice("Dummy", "first device")
		assert.Nil(t, err)
		devices, err := signatureService.GetDevices()
		assert.Nil(t, err)
		assert.Len(t, devices, 1)
		device := devices[0]
		assert.Equal(t, 0, device.Counter)
		assert.Equal(t, deviceId, device.ID)
	})
}

func TestListSignatureDevice(t *testing.T) {
	t.Run("Empty list", func(t *testing.T) {
		repository := NewFakeRepository()
		signatureService, err := NewSignatureService(testAlgorithms, repository)
		require.Nil(t, err)
		devices, err := signatureService.GetDevices()
		assert.Nil(t, err)
		assert.Len(t, devices, 0)
	})
	t.Run("Not empty list", func(t *testing.T) {
		repository := NewFakeRepository()
		signatureService, err := NewSignatureService(testAlgorithms, repository)
		require.Nil(t, err)
		_, err = signatureService.NewSignatureDevice("Dummy", "first device")
		require.Nil(t, err)
		devices, err := signatureService.GetDevices()
		assert.Nil(t, err)
		assert.Len(t, devices, 1)
	})
}
