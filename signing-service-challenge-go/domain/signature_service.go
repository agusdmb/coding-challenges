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

type Repository interface {
	SaveDevice(device *StoredDevice) error
	GetDevice(id uuid.UUID) (*StoredDevice, error)
	GetDevices() ([]*StoredDevice, error)
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

func (s *SignatureService) SignData(device_id uuid.UUID, message string) (string, string, error) {
	// TODO: This mutex can be farther improve to avoid locking for all devices
	// at the same time
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
