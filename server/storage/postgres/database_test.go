package postgres

import (
	"context"
	"testing"

	"github.com/MaximMNsk/go-secure-storage/server/config"
)

func TestStorage_SaveUser(t *testing.T) {
	cfg := config.Config{DatabaseConnectionString: `postgresql://postgres@127.0.0.1:5432/postgres?sslmode=disable`}
	db := Storage{}
	db.Init(context.Background(), cfg)
	_, _, err := db.SaveUser(context.Background(), `asd`, `zxc`, `qwe`, `123`, nil)
	t.Log(err)
}
