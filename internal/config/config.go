package config

import (
	"fmt"
	"os"
	"strconv"
)

type DBConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
}

type JWTConfig struct {
	SecretKey  string
	Issuer     string
	Audience   string
	CookieName string
	ExpireDays int
}

type KafkaConfig struct {
	Host string
	Port string
}

type CredConfig struct {
	LoginChars     string
	MaxLoginLength int
	MinLoginLength int
	PwdChars       string
	MaxPwdLength   int
	MinPwdLength   int
}

type Config struct {
	Env      string
	RestPort string
	GrpcPort string
	DB       DBConfig
	JWT      JWTConfig
	Kafka    KafkaConfig
	Cred     CredConfig
}

func Load() (*Config, error) {
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
			User:     getEnvString("POSTGRES_USER"),
			Password: getEnvString("POSTGRES_PASSWORD"),
			DBName:   getEnvString("POSTGRES_DB"),
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
