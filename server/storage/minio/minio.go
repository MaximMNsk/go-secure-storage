package minio

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/MaximMNsk/go-secure-storage/server/config"
)

type Storage struct {
	Client *minio.Client
}

// MinioStorage - структура работы с хранилищем Минио.
//
//go:generate go run github.com/vektra/mockery/v2@v2.43.0 --name=MinioStorage
type MinioStorage interface {
	Init(_ context.Context, config config.Config) error
	Destroy() error
	Ping(_ context.Context) bool
	PutObject(ctx context.Context, userID, objectName string, object []byte) error
	GetObject(ctx context.Context, userID, name string) ([]byte, error)
	ListObjects(ctx context.Context, userID string) ([]string, error)
}

// Init - насыщение структуры.
func (m *Storage) Init(_ context.Context, config config.Config) error {
	var err error
	m.Client, err = minio.New(config.Minio.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV2(config.Minio.AccessKey, config.Minio.SecretKey, ``),
		Secure: config.Minio.UseSSL,
	})
	return err
}

// Destroy - безопасный останов.
func (m *Storage) Destroy() error {
	return nil
}

// Ping - проверка работоспособности.
func (m *Storage) Ping(_ context.Context) bool {
	hc, err := m.Client.HealthCheck(1 * time.Second)
	defer hc()
	if err != nil {
		return false
	}
	return m.Client.IsOnline()
}

// PutObject - отправка объекта в хранилище.
func (m *Storage) PutObject(ctx context.Context, userID, objectName string, object []byte) error {
	bucketName := `bucket-` + userID
	exists, err := m.Client.BucketExists(ctx, bucketName)
	if err != nil && !strings.Contains(err.Error(), `The specified bucket is not valid`) {
		return err
	}
	if !exists {
		err = m.Client.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{ObjectLocking: true})
		if err != nil {
			return err
		}
	}

	objects, err := m.ListObjects(ctx, userID)
	if err != nil {
		return err
	}

	for _, obj := range objects {
		if objectName == obj {
			return errors.New("object already exists")
		}
	}

	reader := bytes.NewReader(object)

	_, err = m.Client.PutObject(ctx, bucketName, objectName, reader, reader.Size(), minio.PutObjectOptions{ContentType: "application/octet-stream"})
	if err != nil {
		return err
	}
	return nil
}

// GetObject - получение объекта из хранилища.
func (m *Storage) GetObject(ctx context.Context, userID, name string) ([]byte, error) {
	bucketName := `bucket-` + userID
	objects, err := m.ListObjects(ctx, userID)
	if err != nil {
		return nil, err
	}
	isFound := false
	for _, obj := range objects {
		if name == obj {
			isFound = true
		}
	}
	if !isFound {
		return nil, errors.New("object not found")
	}
	object, err := m.Client.GetObject(ctx, bucketName, name, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	objectData, err := io.ReadAll(object)
	if err != nil {
		return nil, err
	}
	return objectData, nil
}

// ListObjects - получение списка объектов в хранилище.
func (m *Storage) ListObjects(ctx context.Context, userID string) ([]string, error) {
	bucketName := `bucket-` + userID
	opts := minio.ListObjectsOptions{
		//UseV1:     true,
		Prefix:    "",
		Recursive: false,
	}
	var result []string
	for object := range m.Client.ListObjects(ctx, bucketName, opts) {
		if object.Err != nil {
			return nil, object.Err
		}
		result = append(result, object.Key)
	}
	return result, nil
}
