package domain

import (
	"errors"

	"github.com/google/uuid"
)

func NewFakeRepository() *FakeRepository {
	devices := make(map[uuid.UUID]*StoredDevice)
	return &FakeRepository{devices: devices}
}

type FakeRepository struct {
	devices map[uuid.UUID]*StoredDevice
}

func (r *FakeRepository) SaveDevice(device *StoredDevice) error {
	r.devices[device.Id] = device
	return nil
}

func (r *FakeRepository) GetDevice(id uuid.UUID) (*StoredDevice, error) {
	device, ok := r.devices[id]
	if !ok {
		return nil, errors.New("Device not found")
	}
	return device, nil
}

func (r *FakeRepository) GetDevices() ([]*StoredDevice, error) {
	devices := make([]*StoredDevice, 0)
	for _, device := range r.devices {
		devices = append(devices, device)
	}
	return devices, nil
}
