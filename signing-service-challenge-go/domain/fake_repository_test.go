package domain

import (
	"errors"

	"github.com/google/uuid"
)

func NewInMemoryRepository() *InMemoryRepository {
	devices := make(map[uuid.UUID]*StoredDevice)
	return &InMemoryRepository{devices: devices}
}

type InMemoryRepository struct {
	devices map[uuid.UUID]*StoredDevice
}

func (r *InMemoryRepository) SaveDevice(device *StoredDevice) error {
	r.devices[device.Id] = device
	return nil
}

func (r *InMemoryRepository) GetDevice(id uuid.UUID) (*StoredDevice, error) {
	device, ok := r.devices[id]
	if !ok {
		return nil, errors.New("Device not found")
	}
	return device, nil
}

func (r *InMemoryRepository) GetDevices() ([]*StoredDevice, error) {
	devices := make([]*StoredDevice, 0)
	for _, device := range r.devices {
		devices = append(devices, device)
	}
	return devices, nil
}
