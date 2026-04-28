package auth

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/kkonst40/sso-service/internal/config"
	"github.com/kkonst40/sso-service/internal/model"
)

type ctxKey struct{}

var userIDKey ctxKey

func GetUserID(ctx context.Context) uuid.UUID {
	return ctx.Value(userIDKey).(uuid.UUID)
}

func ContextWithUserID(ctx context.Context, userID uuid.UUID) context.Context {
	return context.WithValue(ctx, userIDKey, userID)
}

type UserClaims struct {
	ID        uuid.UUID `json:"id"`
	UserName  string    `json:"userName"`
	SessionID uuid.UUID `json:"sid"`
	jwt.RegisteredClaims
}

type JWTProvider struct {
	issuer    string
	audience  string
	secretKey string
	ttl       time.Duration
}

func NewJWTProvider(cfg *config.Config) *JWTProvider {
	return &JWTProvider{
		issuer:    cfg.JWT.Issuer,
		audience:  cfg.JWT.Audience,
		secretKey: cfg.JWT.SecretKey,
		ttl:       time.Duration(cfg.JWT.ExpireDays) * 24 * time.Hour,
	}
}

func (p *JWTProvider) Generate(user *model.User, session *model.Session) (string, error) {
	claims := UserClaims{
		ID:        user.ID,
		UserName:  user.Login,
		SessionID: session.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   p.issuer,
			Audience: []string{p.audience},
			ExpiresAt: jwt.NewNumericDate(
				time.Now().Add(p.ttl),
			),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(p.secretKey))
}

func (p *JWTProvider) ValidateToken(tokenString string) (uuid.UUID, error) {
	claims := &UserClaims{}

	token, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		func(token *jwt.Token) (any, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(p.secretKey), nil
		},
		jwt.WithIssuer(p.issuer),
		jwt.WithAudience(p.audience),
	)

	if err != nil {
		return uuid.Nil, err
	}

	if !token.Valid {
		return uuid.Nil, jwt.ErrTokenInvalidClaims
	}

	return claims.ID, nil
}

func (p *JWTProvider) GetTTLDays() int {
	return int(p.ttl.Hours()+1) / 24
}
