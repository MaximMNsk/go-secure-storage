package storage_interface

import (
	"context"

	"github.com/MaximMNsk/go-secure-storage/server/config"
)

type Storable interface {
	Init(ctx context.Context, config config.Config) error
	Destroy() error
	Ping(ctx context.Context) bool
}
