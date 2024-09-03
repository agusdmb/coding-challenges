package persistence

import (
	"errors"

	"github.com/fiskaly/coding-challenges/signing-service-challenge/domain"
	"github.com/google/uuid"
)

func NewInMemoryRepository() *InMemoryRepository {
	devices := make(map[uuid.UUID]*domain.StoredDevice)
	return &InMemoryRepository{devices: devices}
}

type InMemoryRepository struct {
	devices map[uuid.UUID]*domain.StoredDevice
}

func (r *InMemoryRepository) SaveDevice(device *domain.StoredDevice) error {
	r.devices[device.Id] = device
	return nil
}

func (r *InMemoryRepository) GetDevice(id uuid.UUID) (*domain.StoredDevice, error) {
	device, ok := r.devices[id]
	if !ok {
		return nil, errors.New("Device not found")
	}
	return device, nil
}

func (r *InMemoryRepository) GetDevices() ([]*domain.StoredDevice, error) {
	devices := make([]*domain.StoredDevice, 0)
	for _, device := range r.devices {
		devices = append(devices, device)
	}
	return devices, nil
}
