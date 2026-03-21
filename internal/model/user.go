package model

import "github.com/google/uuid"

type User struct {
	ID           uuid.UUID
	Login        string
	PasswordHash string
}

type UserInfo struct {
	ID    uuid.UUID
	Login string
}
