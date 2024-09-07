package config

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
)

// Config - основная структура конфигурации.
type Config struct {
	AppAddr                  string `json:"app_addr"`
	DatabaseConnectionString string `json:"db_connection_string"`
	DatabaseMigrations       string `json:"db_migrations"`
	Minio                    struct {
		Endpoint  string `json:"endpoint"`
		AccessKey string `json:"access_key"`
		SecretKey string `json:"secret_key"`
		UseSSL    bool   `json:"use_ssl"`
	}
	Keys struct {
		Pair1   string
		Pair2   string
		Default struct {
			Pair1 string `json:"pair1"`
			Pair2 string `json:"pair2"`
		}
	}
	ConfigFile string
	Tlc        struct {
		PrivatePath string `json:"private_path"`
		PublicPath  string `json:"public_path"`
	}
}

// Init - заполнение структуры конфигурации.
func (c *Config) Init() error {
	if flag.Lookup(`c`) == nil {
		if len(c.ConfigFile) == 0 {
			flag.StringVar(&c.ConfigFile, "c", "./server.json", "config file path. by default - in the same directory")
		}
	}
	if flag.Lookup(`key1`) == nil {
		flag.StringVar(&c.Keys.Pair1, "key1", "", "enter first key pair")
	}
	if flag.Lookup(`key2`) == nil {
		flag.StringVar(&c.Keys.Pair2, "key2", "", "enter second key pair")
	}
	flag.Parse()

	if len(c.ConfigFile) == 0 {
		return errors.New("config file path is empty")
	}
	_, err := os.Stat(c.ConfigFile)
	if err != nil {
		return err
	}
	file, err := os.Open(c.ConfigFile)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err = file.Close()
	}(file)
	if err != nil {
		return err
	}

	bFile, err := io.ReadAll(file)
	if err != nil {
		return err
	}
	err = json.Unmarshal(bFile, &c)
	if err != nil {
		return err
	}

	return nil
}
