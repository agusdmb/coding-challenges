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
	Marshal(KeyPair T) ([]byte, []byte, error)
	Unmarshal(privateKeyBytes []byte) (T, error)
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

type Repository interface {
	SaveDevice(device *StoredDevice) error
	GetDevice(id uuid.UUID) (*StoredDevice, error)
	GetDevices() ([]*StoredDevice, error)
}

// The signature service can manage multiple signature devices. Such a device
// is identified by a unique identifier (e.g. UUID). For now you can pretend
// there is only one user / organization using the system (e.g. a dedicated
// node for them), therefore you do not need to think about user management at
// all.
type SignatureService struct {
	respository Repository
	algorithms  map[string]Algorithm[KeyPair]
	mutex       sync.Mutex
}

func NewSignatureService(algorithms map[string]Algorithm[KeyPair], repository Repository) (*SignatureService, error) {
	if len(algorithms) == 0 {
		return nil, errors.New("algorithms cannot be empty")
	}
	return &SignatureService{
		respository: repository,
		algorithms:  algorithms,
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

	newDevice := SignatureDevice{
		id:        deviceId,
		algorithm: algorithm_name,
		keyPair:   keyPair,
		label:     label,
	}

	err = s.SaveDevice(&newDevice)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("Could not save device: %w", err)
	}

	return deviceId, nil
}

func (s *SignatureService) SaveDevice(device *SignatureDevice) error {
	marshalDevice, err := s.marshalDevice(device)
	if err != nil {
		return fmt.Errorf("Could not marshal device: %w", err)
	}
	err = s.respository.SaveDevice(marshalDevice)
	if err != nil {
		return fmt.Errorf("Could not save device: %w", err)
	}
	return nil
}

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

func (s *SignatureService) SignData(device_id uuid.UUID, message string) (string, string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	device, err := s.getDevice(device_id)
	if err != nil {
		return "", "", fmt.Errorf("Couldn't get device: %w", err)
	}

	algorithm, ok := s.algorithms[device.algorithm]
	if !ok {
		return "", "", fmt.Errorf("Algorithm %s not found", device.algorithm)
	}

	secureData := generateSecureDataToBeSign(device.signatureCounter, message, device.lastSignatureBase64, device_id)
	signedData, err := algorithm.SignData(secureData, device.keyPair)
	if err != nil {
		return "", "", fmt.Errorf("Error signing data: %w", err)
	}
	signedDataBase64 := base64.StdEncoding.EncodeToString(signedData)
	device.signatureCounter++
	device.lastSignatureBase64 = signedDataBase64
	err = s.SaveDevice(device)
	if err != nil {
		return "", "", fmt.Errorf("Error storing signing data: %w", err)
	}
	return signedDataBase64, secureData, nil
}

type DeviceInfo struct {
	ID        uuid.UUID
	Label     string
	Algorithm string
	Counter   int
}

func (s *SignatureService) GetDevices() ([]DeviceInfo, error) {
	storedDevices, err := s.respository.GetDevices()
	if err != nil {
		return nil, fmt.Errorf("Couldn't get devices: %w", err)
	}

	devices := make([]DeviceInfo, 0)
	for _, device := range storedDevices {
		devices = append(devices, DeviceInfo{
			ID:        device.Id,
			Label:     device.Label,
			Algorithm: device.Algorithm,
			Counter:   device.SignatureCounter,
		})
	}
	return devices, nil
}

// The signature device should also have a label that can be used to display it
// in the UI and a signature_counter that tracks how many signatures have been
// created with this device. The label is provided by the user. The
// signature_counter shall only be modified internally.
type SignatureDevice struct {
	id                  uuid.UUID
	algorithm           string
	keyPair             KeyPair
	label               string
	signatureCounter    int
	lastSignatureBase64 string
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
