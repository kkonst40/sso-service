package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	errs "github.com/kkonst40/isso/internal/errors"
	"github.com/kkonst40/isso/internal/model"
	"github.com/kkonst40/isso/internal/repo"
	"github.com/kkonst40/isso/internal/utils"
)

type UserService struct {
	jwtProvider   *utils.JWTProvider
	pwdHandler    *utils.PasswordHandler
	credValidator *utils.CredValidator
	userRepo      *repo.UserRepo
	specialID     uuid.UUID
}

func New(
	jwtProvider *utils.JWTProvider,
	pwdHandler *utils.PasswordHandler,
	credValidator *utils.CredValidator,
	userRepo *repo.UserRepo,
	specialID uuid.UUID,
) *UserService {
	return &UserService{
		jwtProvider:   jwtProvider,
		pwdHandler:    pwdHandler,
		credValidator: credValidator,
		userRepo:      userRepo,
		specialID:     specialID,
	}
}

func (s *UserService) All(ctx context.Context) ([]model.User, error) {
	return s.userRepo.GetAll(ctx)
}

func (s *UserService) GetLoginsByIDs(ctx context.Context, userIDs []uuid.UUID) ([]model.UserInfo, error) {
	userInfos, err := s.userRepo.GetLoginsByIDs(ctx, userIDs)
	if err != nil {
		return nil, fmt.Errorf("get logins by IDs: %w", err)
	}

	return userInfos, nil
}

func (s *UserService) GetIDsByLogins(ctx context.Context, userLogins []string) ([]model.UserInfo, error) {
	userInfos, err := s.userRepo.GetIDsByLogins(ctx, userLogins)
	if err != nil {
		return nil, fmt.Errorf("get IDs by logins: %w", err)
	}

	return userInfos, nil
}

func (s *UserService) Exist(ctx context.Context, IDs []uuid.UUID) ([]uuid.UUID, error) {
	ids, err := s.userRepo.Exist(ctx, IDs)
	if err != nil {
		return nil, fmt.Errorf("check users existence: %w", err)
	}

	return ids, nil
}

func (s *UserService) Login(ctx context.Context, login, password string) (string, error) {
	user, err := s.userRepo.GetByLogin(ctx, login)
	if err != nil {
		if errors.Is(err, errs.ErrUserNotFound) {
			return "", errs.ErrInvalidCredentials
		}
		return "", fmt.Errorf("get user by login '%v' to log in: %w", login, err)
	}

	if !s.pwdHandler.VerifyPwd(password, user.PasswordHash) {
		return "", errs.ErrInvalidCredentials
	}

	token, err := s.jwtProvider.Generate(user)
	if err != nil {
		return "", fmt.Errorf("%w: jwt token: %w", errs.ErrGenerating, err)
	}

	return token, nil
}

func (s *UserService) Create(ctx context.Context, login, password string) error {
	if !s.credValidator.ValidateLogin(login) {
		return errs.ErrInvalidLogin
	}
	if !s.credValidator.ValidatePwd(password) {
		return errs.ErrInvalidPwd
	}

	userID, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("%w: user id: %w", errs.ErrGenerating, err)
	}
	pwdHash, err := s.pwdHandler.GeneratePwdHash(password)
	if err != nil {
		return fmt.Errorf("%w: password hash: %w", errs.ErrGenerating, err)
	}

	user := &model.User{
		ID:           userID,
		Login:        login,
		PasswordHash: pwdHash,
		TokenID:      uuid.New(),
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return fmt.Errorf("create user: %w", err)
	}

	return nil
}

func (s *UserService) UpdateLogin(ctx context.Context, ID uuid.UUID, newLogin string) error {
	if !s.credValidator.ValidateLogin(newLogin) {
		return errs.ErrInvalidLogin
	}

	user, err := s.userRepo.GetByID(ctx, ID)
	if err != nil {
		return fmt.Errorf("get user %v to update: %w", ID, err)
	}

	user.Login = newLogin

	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("update user %v: %w", ID, err)
	}

	return nil
}

func (s *UserService) UpdatePassword(ctx context.Context, ID uuid.UUID, newPwd string) error {
	if !s.credValidator.ValidatePwd(newPwd) {
		return errs.ErrInvalidPwd
	}

	user, err := s.userRepo.GetByID(ctx, ID)
	if err != nil {
		return fmt.Errorf("get user %v to update: %w", ID, err)
	}

	newPwdHash, err := s.pwdHandler.GeneratePwdHash(newPwd)
	if err != nil {
		return fmt.Errorf("%w: password hash: %w", errs.ErrGenerating, err)
	}

	user.PasswordHash = newPwdHash

	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("update user %v: %w", ID, err)
	}

	return nil
}

func (s *UserService) Delete(ctx context.Context, ID, requesterID uuid.UUID) error {
	if requesterID != ID && requesterID != s.specialID {
		return errs.ErrForbidden
	}

	if err := s.userRepo.Delete(ctx, ID); err != nil {
		return fmt.Errorf("delete user %v: %w", ID, err)
	}

	return nil
}

func (s *UserService) Logout(ctx context.Context, ID uuid.UUID) error {
	user, err := s.userRepo.GetByID(ctx, ID)
	if err != nil {
		return fmt.Errorf("get user %v to log out: %w", ID, err)
	}

	user.TokenID = uuid.New()
	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("update user %v token ID: %w", ID, err)
	}

	return nil
}
