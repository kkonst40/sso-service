package middleware

import (
	"net/http"
	"time"
)

func Timeout(d time.Duration) Middleware {
	return func(next http.Handler) http.Handler {
		return http.TimeoutHandler(next, d, "Timed out")
	}
}
