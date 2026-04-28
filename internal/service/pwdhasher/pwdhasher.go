package pwdhasher

import "golang.org/x/crypto/bcrypt"

type PasswordHasher struct{}

func New() *PasswordHasher {
	return &PasswordHasher{}
}

func (h *PasswordHasher) GeneratePwdHash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func (h *PasswordHasher) VerifyPwd(password string, passwordHash string) bool {
	err := bcrypt.CompareHashAndPassword(
		[]byte(passwordHash),
		[]byte(password),
	)
	return err == nil
}
