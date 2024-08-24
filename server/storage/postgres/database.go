package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/MaximMNsk/go-secure-storage/server/config"
)

type Storage struct {
	Pool   *pgxpool.Pool
	Config *config.Config
}

func (d *Storage) Init(ctx context.Context, config config.Config) error {
	d.Config = &config
	cfg, err := pgxpool.ParseConfig(config.DatabaseConnectionString)
	if err != nil {
		return err
	}
	cfg.MaxConns = 16
	cfg.MinConns = 1
	cfg.HealthCheckPeriod = 1 * time.Minute
	cfg.MaxConnLifetime = 1 * time.Hour
	cfg.MaxConnIdleTime = 1 * time.Minute
	cfg.ConnConfig.ConnectTimeout = 10 * time.Second

	d.Pool, err = pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return err
	}

	err = d.prepare()
	if err != nil {
		return err
	}
	return nil
}

func (d *Storage) Destroy() error {
	d.Pool.Close()
	stat := d.Pool.Stat()
	if stat.TotalConns() > 0 {
		return errors.New(`not all connections have been closed`)
	}
	return nil
}

func (d *Storage) Ping(ctx context.Context) bool {
	err := d.Pool.Ping(ctx)
	return err == nil
}

func (d *Storage) prepare() error {
	m, err := migrate.New(
		`file://`+d.Config.DatabaseMigrations,
		d.Config.DatabaseConnectionString)
	if err != nil {
		return err
	}
	err = m.Up()
	if err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			return nil
		}
		return err
	}

	return nil
}

const (
	saveUserSql = `INSERT INTO users (user_name, user_second_name, user_login, user_pwd_hash) 
					VALUES ($1, $2, $3, $4)
					RETURNING id`
	getUserByLoginSql = `SELECT id, CONCAT(user_second_name, ' ', user_name) as credentials,
       						user_pwd_hash as pwd_hash
						FROM users WHERE user_login = $1`
	setUserKeySql        = `INSERT INTO user_keys (user_id, user_key) VALUES ($1, $2)`
	disableUserKeysSql   = `UPDATE user_keys SET is_active = false WHERE user_id = $1 and is_active = true`
	getUserKeyByLoginSql = `SELECT uk.user_key::bytea as key
							FROM user_keys uk
							LEFT JOIN users u
							ON uk.user_id = u.id
							WHERE u.user_login = $1
							AND uk.is_active = true`
	saveUserDataSql = `INSERT INTO user_data (user_id, data_type, user_data) VALUES ($1, $2, $3)`
	getUserDataSql  = `SELECT user_data::bytea FROM user_data WHERE user_id = $1 and data_type = $2`
)

// SaveUser - сохраняем пользователя. Возвращаем:
// userID, duplicate, error
func (d *Storage) SaveUser(ctx context.Context, name, secondName, login, pwdHash string, userKey []byte) (int, bool, error) {
	var id int
	query := d.Pool.QueryRow(ctx, saveUserSql, name, secondName, login, pwdHash)
	err := query.Scan(&id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr); pgErr.Code == pgerrcode.UniqueViolation {
			return -1, true, errors.New(`user already exists`)
		}
		return -1, false, err
	}
	_, err = d.Pool.Exec(ctx, setUserKeySql, id, userKey)
	if err != nil {
		return -1, false, err
	}

	return id, false, nil
}

// GetUserByLogin - возвращает инфо о пользователе:
// id, credentials, pwd_hash error
func (d *Storage) GetUserByLogin(ctx context.Context, login string) (int, string, string, error) {
	var credentials, pwdHash string
	var id int
	query := d.Pool.QueryRow(ctx, getUserByLoginSql, login)
	err := query.Scan(&id, &credentials, &pwdHash)
	if err != nil {
		return 0, "", "", err
	}
	return id, credentials, pwdHash, nil
}

func (d *Storage) SetUserKey(ctx context.Context, userID int, key []byte) error {
	_, err := d.Pool.Exec(ctx, setUserKeySql, userID, key)
	if err != nil {
		return err
	}
	return nil
}

func (d *Storage) DisableUserKeys(ctx context.Context, userID int) error {
	_, err := d.Pool.Exec(ctx, disableUserKeysSql, userID)
	if err != nil {
		return err
	}
	return nil
}

func (d *Storage) GetUserKeyByLogin(ctx context.Context, login string) ([]byte, error) {
	var key []byte
	query := d.Pool.QueryRow(ctx, getUserKeyByLoginSql, login)
	err := query.Scan(&key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (d *Storage) SaveUserData(ctx context.Context, userID int, dataType string, data []byte) error {
	_, err := d.Pool.Exec(ctx, saveUserDataSql, userID, dataType, data)
	if err != nil {
		return err
	}
	return nil
}

func (d *Storage) GetUserData(ctx context.Context, userID int, dataType string) ([][]byte, error) {
	var dataList [][]byte
	query, err := d.Pool.Query(ctx, getUserDataSql, userID, dataType)
	if err != nil {
		return nil, err
	}
	for query.Next() {
		var data []byte
		err = query.Scan(&data)
		if err != nil {
			return nil, err
		}
		dataList = append(dataList, data)
	}
	return dataList, nil
}
