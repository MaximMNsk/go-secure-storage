package memory

import (
	"context"
	"errors"

	"github.com/MaximMNsk/go-secure-storage/server/config"
)

type Storage struct {
	items map[string]string
}

func (m *Storage) Init(_ context.Context, _ config.Config) error {
	m.items = make(map[string]string)
	return nil
}

func (m *Storage) Destroy() error {
	m.items = nil
	if len(m.items) > 0 {
		return errors.New(`cannot destroy memory storage`)
	}
	return nil
}

func (m *Storage) Ping(_ context.Context) bool {
	return m.items != nil
}

type StorageActions interface {
	Set(key string, value string) error
	ReSet(key string, value string) error
	Get(key string) (string, error)
}

func (m *Storage) Set(key string, value string) error {
	if _, ok := m.items[key]; !ok {
		m.items[key] = value
		return nil
	}
	return errors.New(`key already exists`)
}

func (m *Storage) ReSet(key string, value string) error {
	m.items[key] = value
	return nil
}

func (m *Storage) Get(key string) (string, error) {
	if value, ok := m.items[key]; ok {
		return value, nil
	}
	return ``, errors.New(`key doesn't exists`)
}
