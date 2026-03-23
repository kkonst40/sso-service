package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
)

type DBConfig struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	DBName   string `json:"dbname"`
}

type JWTConfig struct {
	SecretKey  string `json:"secretKey"`
	Issuer     string `json:"issuer"`
	Audience   string `json:"audience"`
	CookieName string `json:"cookieName"`
	ExpireDays int    `json:"expireDays"`
}

type KafkaConfig struct {
	Host string `json:"host"`
	Port string `json:"port"`
}

type CredConfig struct {
	LoginChars     string `json:"loginChars"`
	MaxLoginLength int    `json:"maxLoginLength"`
	MinLoginLength int    `json:"minLoginLength"`
	PwdChars       string `json:"passwordChars"`
	MaxPwdLength   int    `json:"maxPasswordLength"`
	MinPwdLength   int    `json:"minPasswordLength"`
}

type Config struct {
	Env      string      `json:"env"`
	RestPort string      `json:"restPort"`
	GrpcPort string      `json:"grpcPort"`
	DB       DBConfig    `json:"db"`
	JWT      JWTConfig   `json:"jwt"`
	Kafka    KafkaConfig `json:"kafka"`
	Cred     CredConfig  `json:"cred"`
}

func Load() (*Config, error) {
	var cfg *Config
	var err error
	switch runtime.GOOS {
	case "windows":
		cfg, err = loadConfigJSON()
	case "linux":
		cfg, err = loadConfigEnv()
	default:
		return nil, fmt.Errorf("config loading error")
	}

	return cfg, err
}

func loadConfigEnv() (*Config, error) {
	var (
		errMissing error
		errNotInt  error
		errResult  error
	)

	getEnvString := func(key string) string {
		val, ok := os.LookupEnv(key)
		if !ok {
			if errMissing == nil {
				errMissing = fmt.Errorf("missing environment variables: %s", key)
			} else {
				errMissing = fmt.Errorf("%w, %s", errMissing, key)
			}
			return ""
		}
		return val
	}

	getEnvInt := func(key string) int {
		val, ok := os.LookupEnv(key)
		if !ok {
			if errMissing == nil {
				errMissing = fmt.Errorf("missing environment variables: %s", key)
			} else {
				errMissing = fmt.Errorf("%w, %s", errMissing, key)
			}
			return 0
		}

		valInt, err := strconv.Atoi(val)
		if err != nil {
			if errNotInt == nil {
				errNotInt = fmt.Errorf("environment variables must be integer: %s", val)
			} else {
				errNotInt = fmt.Errorf("%w, %s", errNotInt, val)
			}
			return 0
		}

		return valInt
	}

	cfg := &Config{
		Env:      getEnvString("ENV"),
		RestPort: getEnvString("REST_PORT"),
		GrpcPort: getEnvString("GRPC_PORT"),
		DB: DBConfig{
			Host:     getEnvString("DB_HOST"),
			Port:     getEnvString("DB_PORT"),
			User:     getEnvString("DB_USER"),
			Password: getEnvString("DB_PASSWORD"),
			DBName:   getEnvString("DB_NAME"),
		},
		JWT: JWTConfig{
			SecretKey:  getEnvString("JWT_SECRET"),
			Issuer:     getEnvString("JWT_ISSUER"),
			Audience:   getEnvString("JWT_AUDIENCE"),
			CookieName: getEnvString("JWT_COOKIE"),
			ExpireDays: getEnvInt("JWT_EXPIREDAYS"),
		},
		Kafka: KafkaConfig{
			Host: getEnvString("KAFKA_HOST"),
			Port: getEnvString("KAFKA_PORT"),
		},
		Cred: CredConfig{
			LoginChars:     getEnvString("CRED_LOGIN_CHARS"),
			MaxLoginLength: getEnvInt("CRED_MAX_LOGIN_LENGTH"),
			MinLoginLength: getEnvInt("CRED_MIN_LOGIN_LENGTH"),
			PwdChars:       getEnvString("CRED_PASSWORD_CHARS"),
			MaxPwdLength:   getEnvInt("CRED_MAX_PASSWORD_LENGTH"),
			MinPwdLength:   getEnvInt("CRED_MIN_PASSWORD_LENGTH"),
		},
	}

	if errMissing != nil {
		errResult = errMissing
	}

	if errNotInt != nil {
		if errResult == nil {
			errResult = errNotInt
		} else {
			errResult = fmt.Errorf("%w; %w", errResult, errNotInt)
		}
	}

	if errResult != nil {
		return nil, errResult
	}

	return cfg, nil
}

func loadConfigJSON() (*Config, error) {
	exePath, err := os.Executable()
	if err != nil {
		return nil, err
	}

	currDir := filepath.Dir(exePath)
	file, err := os.Open(filepath.Join(currDir, "config.json"))
	if err != nil {
		return nil, fmt.Errorf("json config file oppening error: %v", err)
	}
	defer file.Close()

	var cfg Config
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("json config file reading error: %v", err)
	}

	return &cfg, nil
}
