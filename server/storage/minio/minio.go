package minio

import (
	"context"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/MaximMNsk/go-secure-storage/server/config"
)

type Storage struct {
	Client *minio.Client
}

func (m *Storage) Init(_ context.Context, config config.Config) error {
	var err error
	m.Client, err = minio.New(config.Minio.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV2(config.Minio.AccessKey, config.Minio.SecretKey, ``),
		Secure: config.Minio.UseSSL,
	})
	return err
}

func (m *Storage) Destroy() error {
	return nil
}

func (m *Storage) Ping(_ context.Context) bool {
	hc, err := m.Client.HealthCheck(1 * time.Second)
	defer hc()
	if err != nil {
		return false
	}
	return m.Client.IsOnline()
}
