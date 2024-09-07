package postgres

import (
	"context"
	"errors"
	"github.com/MaximMNsk/go-secure-storage/server/config"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/require"
	"regexp"
	"testing"
)

// go test -timeout 10s -v $(go list ./... | grep -v test) -coverprofile=profile.cov && go tool cover -func profile.cov

var Cfg = `../../../cmd/server/server.json`

func TestStorage_SaveUser(t *testing.T) {
	type user struct {
		name       string
		secondName string
		login      string
		pwdHash    string
		userKey    []byte
	}
	type args struct {
		ctx        context.Context
		cfg        config.Config
		user       user
		existsUser user
	}
	type want struct {
		err error
	}
	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: "success",
			args: args{
				ctx: context.Background(),
				cfg: config.Config{
					ConfigFile: Cfg,
				},
				user:       user{name: `asd`, secondName: `zxc`, login: `qwe`, pwdHash: ``, userKey: []byte(``)},
				existsUser: user{name: `asd`, secondName: `zxc`, login: `qwe`, pwdHash: ``, userKey: []byte(``)},
			},
			want: want{err: nil},
		},
		{
			name: `already exists`,
			args: args{
				ctx: context.Background(),
				cfg: config.Config{
					ConfigFile: Cfg,
				},
				user:       user{name: `asd`, secondName: `zxc`, login: `qwe`, pwdHash: `qwe`, userKey: []byte(``)},
				existsUser: user{name: `asd`, secondName: `zxc`, login: `qwe`, pwdHash: `qwe`, userKey: []byte(``)},
			},
			want: want{err: errors.New(`user already exists`)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.args.cfg.Init()
			require.NoError(t, err)

			mockPool, err := pgxmock.NewPool()
			require.NoError(t, err)
			defer mockPool.Close()

			if tt.name == "success" {
				row := mockPool.NewRows([]string{`1`}).AddRow(1)
				mockPool.
					ExpectQuery(regexp.QuoteMeta(saveUserSql)).
					WithArgs(tt.args.existsUser.name, tt.args.existsUser.secondName, tt.args.existsUser.login, tt.args.existsUser.pwdHash).
					WillReturnRows(row)
				commandTag := pgconn.NewCommandTag(`INSERT 0`)
				mockPool.
					ExpectExec(regexp.QuoteMeta(setUserKeySql)).
					WithArgs(1, []byte(``)).
					WillReturnResult(commandTag)
			}
			if tt.name == "already exists" {
				var pgErr pgconn.PgError
				pgErr.Code = pgerrcode.UniqueViolation
				mockPool.
					ExpectQuery(regexp.QuoteMeta(saveUserSql)).
					WithArgs(tt.args.existsUser.name, tt.args.existsUser.secondName, tt.args.existsUser.login, tt.args.existsUser.pwdHash).
					WillReturnError(&pgErr)
			}

			db := Storage{
				Pool:   mockPool,
				Config: tt.args.cfg,
			}
			_, _, err = db.SaveUser(tt.args.ctx, tt.args.user.name, tt.args.user.secondName, tt.args.user.login, tt.args.user.pwdHash, tt.args.user.userKey)
			require.Equal(t, tt.want.err, err)
		})
	}
}

func TestStorage_GetUserByLogin(t *testing.T) {
	type user struct {
		login string
	}
	type args struct {
		ctx        context.Context
		cfg        config.Config
		user       user
		existsUser struct {
			id          int
			credentials string
			pwdHash     string
		}
	}
	type want struct {
		err error
	}
	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: "success",
			args: args{
				ctx: context.Background(),
				cfg: config.Config{
					ConfigFile: Cfg,
				},
				user: user{login: `qwe`},
				existsUser: struct {
					id          int
					credentials string
					pwdHash     string
				}{id: 1, credentials: `Some user`, pwdHash: `hashedPwd`},
			},
			want: want{err: nil},
		},
		{
			name: `user error`,
			args: args{
				ctx: context.Background(),
				cfg: config.Config{
					ConfigFile: Cfg,
				},
				user: user{login: `qwe`},
				existsUser: struct {
					id          int
					credentials string
					pwdHash     string
				}{id: 1, credentials: `Some user`, pwdHash: `hashedPwd`},
			},
			want: want{err: errors.New(`user not found`)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.args.cfg.Init()
			require.NoError(t, err)

			mockPool, err := pgxmock.NewPool()
			require.NoError(t, err)
			defer mockPool.Close()

			if tt.name == "success" {
				row := mockPool.NewRows([]string{`id`, `credentials`, `pwd_hash`}).
					AddRow(tt.args.existsUser.id, tt.args.existsUser.credentials, tt.args.existsUser.pwdHash)
				mockPool.
					ExpectQuery(regexp.QuoteMeta(getUserByLoginSql)).
					WithArgs(tt.args.user.login).
					WillReturnRows(row)
			}
			if tt.name == "already exists" {
				var pgErr pgconn.PgError
				pgErr.Code = pgerrcode.NoData
				mockPool.
					ExpectQuery(regexp.QuoteMeta(saveUserSql)).
					WithArgs(tt.args.user.login).
					WillReturnError(&pgErr)
			}

			db := Storage{
				Pool:   mockPool,
				Config: tt.args.cfg,
			}
			id, creds, pwd, err := db.GetUserByLogin(tt.args.ctx, tt.args.user.login)
			t.Log(id, creds, pwd)
			require.Equal(t, tt.want.err, err)
		})
	}
}
