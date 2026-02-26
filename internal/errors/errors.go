package errors

import (
	"errors"
	"net/http"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidPwd         = errors.New("invalid password")
	ErrInvalidLogin       = errors.New("invalid login")
	ErrDatabase           = errors.New("internal db error")
	ErrUserNotFound       = errors.New("user not found")
	ErrLoginExists        = errors.New("user already exists")
	ErrForbidden          = errors.New("no permission")
	ErrGenerating         = errors.New("generating error")
)

func MapError(err error) (string, int) {
	if err == nil {
		return "", http.StatusOK
	}

	switch {
	case errors.Is(err, ErrInvalidCredentials):
		return "Invalid login or password", http.StatusUnauthorized

	case errors.Is(err, ErrInvalidLogin):
		return "Invalid login", http.StatusUnprocessableEntity

	case errors.Is(err, ErrInvalidPwd):
		return "Invalid password", http.StatusUnprocessableEntity

	case errors.Is(err, ErrUserNotFound):
		return "User not found", http.StatusNotFound

	case errors.Is(err, ErrLoginExists):
		return "Login already taken", http.StatusConflict

	case errors.Is(err, ErrForbidden):
		return "User has no permission", http.StatusForbidden

	default:
		return "Internal server error", http.StatusInternalServerError
	}
}
