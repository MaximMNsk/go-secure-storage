package postgres

import (
	"context"
	"regexp"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/require"

	"github.com/MaximMNsk/go-secure-storage/server/config"
)

// go test -timeout 10s -v $(go list ./... | grep -v test) -coverprofile=profile.cov && go tool cover -func profile.cov

func TestStorage_SaveUser(t *testing.T) {
	cfg := config.Config{
		ConfigFile: `../../../cmd/server/server.json`,
	}
	err := cfg.Init()
	require.NoError(t, err)

	mockPool, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer func() {
		mockPool.Close()
	}()

	row := mockPool.NewRows([]string{`1`}).AddRow(1)
	mockPool.
		ExpectQuery(regexp.QuoteMeta(saveUserSql)).
		WithArgs(`asd`, `zxc`, `qwe`, ``).WillReturnRows(row)

	commandTag := pgconn.NewCommandTag(`INSERT 0`)
	mockPool.
		ExpectExec(regexp.QuoteMeta(setUserKeySql)).
		WithArgs(1, []byte(``)).
		WillReturnResult(commandTag)

	db := Storage{
		Pool:   mockPool,
		Config: &cfg,
	}
	_, _, err = db.SaveUser(context.Background(), `asd`, `zxc`, `qwe`, ``, nil)
	require.Error(t, err)
}
