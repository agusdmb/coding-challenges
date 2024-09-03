package domain

import (
	"fmt"

	"github.com/google/uuid"
)

func (s *SignatureService) getDevice(id uuid.UUID) (*SignatureDevice, error) {
	storedDevice, err := s.respository.GetDevice(id)
	if err != nil {
		return nil, fmt.Errorf("Could not get device: %w", err)
	}

	device, err := s.unmarshalDevice(storedDevice)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal device: %w", err)
	}

	return device, nil
}

func (s *SignatureService) marshalDevice(device *SignatureDevice) (*StoredDevice, error) {
	publicKeyBytes, privateKeyBytes, err := s.marshal(device)
	if err != nil {
		return nil, err
	}
	storedDevice := StoredDevice{
		Id:                  device.id,
		Algorithm:           device.algorithm,
		Label:               device.label,
		SignatureCounter:    device.signatureCounter,
		LastSignatureBase64: device.lastSignatureBase64,
		PublicKeyBytes:      publicKeyBytes,
		PrivateKeyBytes:     privateKeyBytes,
	}
	return &storedDevice, nil
}

func (s *SignatureService) unmarshalDevice(storedDevice *StoredDevice) (*SignatureDevice, error) {
	keyPair, err := s.unmarshal(storedDevice)
	if err != nil {
		return nil, err
	}

	device := SignatureDevice{
		id:                  storedDevice.Id,
		algorithm:           storedDevice.Algorithm,
		keyPair:             keyPair,
		label:               storedDevice.Label,
		signatureCounter:    storedDevice.SignatureCounter,
		lastSignatureBase64: storedDevice.LastSignatureBase64,
	}
	return &device, nil
}

func (s *SignatureService) marshal(device *SignatureDevice) ([]byte, []byte, error) {
	algorithm, ok := s.algorithms[device.algorithm]
	if !ok {
		return nil, nil, fmt.Errorf("Algorithm %s not found", device.algorithm)
	}

	return algorithm.Marshal(device.keyPair)
}

func (s *SignatureService) unmarshal(storedDevice *StoredDevice) (KeyPair, error) {
	algorithm, ok := s.algorithms[storedDevice.Algorithm]
	if !ok {
		return nil, fmt.Errorf("Algorithm %s not found", storedDevice.Algorithm)
	}

	return algorithm.Unmarshal(storedDevice.PrivateKeyBytes)
}
