package domain

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sync"

	"github.com/google/uuid"
)

// I don't like this solution but since go doesn't have variance i couldn't
// think of anything better
// https://blog.merovius.de/posts/2018-06-03-why-doesnt-go-have-variance-in/
type KeyPair interface{}

type Algorithm[T KeyPair] interface {
	CreateKeyPair() (T, error)
	SignData(data string, keyPair T) ([]byte, error)
}

// The signature service can manage multiple signature devices. Such a device
// is identified by a unique identifier (e.g. UUID). For now you can pretend
// there is only one user / organization using the system (e.g. a dedicated
// node for them), therefore you do not need to think about user management at
// all.
type SignatureService struct {
	algorithms map[string]Algorithm[KeyPair]
	devices    map[uuid.UUID]*signatureDevice
}

func NewSignatureService(algorithms map[string]Algorithm[KeyPair]) (*SignatureService, error) {
	if len(algorithms) == 0 {
		return nil, errors.New("algorithms cannot be empty")
	}
	return &SignatureService{
		devices:    make(map[uuid.UUID]*signatureDevice),
		algorithms: algorithms,
	}, nil
}

// When creating the signature device, the client of the API has to choose the
// signature algorithm that the device will be using to sign transaction data.
// During the creation process, a new key pair (public key & private key) has
// to be generated and assigned to the device.
func (s *SignatureService) NewSignatureDevice(algorithm_name string, label string) (uuid.UUID, error) {
	algorithm, ok := s.algorithms[algorithm_name]
	if !ok {
		return uuid.UUID{}, fmt.Errorf("algorithm %s not in algorithms", algorithm_name)
	}
	deviceId, err := uuid.NewRandom()
	if err != nil {
		return deviceId, fmt.Errorf("Could not generate a UUID for device: %w", err)
	}
	keyPair, err := algorithm.CreateKeyPair()
	if err != nil {
		return deviceId, fmt.Errorf("Could not create a KeyPair for device: %w", err)
	}
	newDevice := signatureDevice{
		id:        deviceId,
		algorithm: algorithm_name,
		keyPair:   keyPair,
		label:     label,
	}
	s.devices[deviceId] = &newDevice
	return deviceId, nil
}

func (s *SignatureService) SignData(device_id uuid.UUID, message string) (string, string, error) {
	device, ok := s.devices[device_id]
	if !ok {
		return "", "", fmt.Errorf("Device %s not found", device_id)
	}

	algorithm, ok := s.algorithms[device.algorithm]
	if !ok {
		return "", "", fmt.Errorf("Algorithm %s not found", device.algorithm)
	}

	device.mutex.Lock()
	defer device.mutex.Unlock()

	secureData := generateSecureDataToBeSign(device.signatureCounter, message, device.lastSignatureBase64, device_id)
	signedData, err := algorithm.SignData(secureData, device.keyPair)
	if err != nil {
		return "", "", fmt.Errorf("Error signing data: %w", err)
	}
	signedDataBase64 := base64.StdEncoding.EncodeToString(signedData)
	device.signatureCounter++
	device.lastSignatureBase64 = signedDataBase64
	return signedDataBase64, secureData, nil
}

type DeviceInfo struct {
	ID        uuid.UUID
	Label     string
	Algorithm string
	Counter   int
}

func (s *SignatureService) GetDevices() []DeviceInfo {
	devices := make([]DeviceInfo, 0)
	for _, device := range s.devices {
		devices = append(devices, DeviceInfo{
			ID:        device.id,
			Label:     device.label,
			Algorithm: device.algorithm,
			Counter:   device.signatureCounter,
		})
	}
	return devices
}

// The signature device should also have a label that can be used to display it
// in the UI and a signature_counter that tracks how many signatures have been
// created with this device. The label is provided by the user. The
// signature_counter shall only be modified internally.
type signatureDevice struct {
	id                  uuid.UUID
	algorithm           string
	keyPair             KeyPair
	label               string
	signatureCounter    int
	lastSignatureBase64 string
	mutex               sync.Mutex
}

// The resulting string (secured_data_to_be_signed) should follow this format:
// <signature_counter>_<data_to_be_signed>_<last_signature_base64_encoded>
//
// In the base case there is no last_signature (= signature_counter == 0). Use
// the base64-encoded device ID (last_signature = base64(device.id)) instead of
// the last_signature.
func generateSecureDataToBeSign(signatureCount int, message string, lastSignatureBase64 string, deviceId uuid.UUID) string {
	if signatureCount == 0 {
		deviceIdBase64 := base64.StdEncoding.EncodeToString(deviceId[:])
		return fmt.Sprintf("%d_%s_%s", signatureCount, message, deviceIdBase64)
	}
	return fmt.Sprintf("%d_%s_%s", signatureCount, message, lastSignatureBase64)
}
