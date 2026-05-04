package handler

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/kkonst40/sso-service/internal/api/dto"
	"github.com/kkonst40/sso-service/internal/config"
	errs "github.com/kkonst40/sso-service/internal/domain/errors"
	"github.com/kkonst40/sso-service/internal/service/auth"
	userservice "github.com/kkonst40/sso-service/internal/service/user"
)

type UserHandler struct {
	userService *userservice.Service
	cfg         *config.Config
}

func New(userService *userservice.Service, cfg *config.Config) *UserHandler {
	return &UserHandler{
		userService: userService,
		cfg:         cfg,
	}
}

func (h *UserHandler) Me(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (h *UserHandler) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req dto.LRUUser
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		log.Println(err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	deviceID, err := uuid.Parse(r.Header.Get("X-Device-Id"))
	if err != nil {
		log.Println(err)
		http.Error(w, "Invalid X-Device-Id header value", http.StatusBadRequest)
		return
	}

	token, err := h.userService.Login(ctx, req.Login, req.Password, deviceID)
	if err != nil {
		log.Println(err)
		errMsg, errCode := errs.MapError(err)
		http.Error(w, errMsg, errCode)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     h.cfg.JWT.CookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // false только для localhost без https
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(60 * 24 * time.Hour),
	})

	w.WriteHeader(http.StatusNoContent)
}

func (h *UserHandler) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requesterID := auth.GetUserID(ctx)

	deviceID, err := uuid.Parse(r.Header.Get("X-Device-Id"))
	if err != nil {
		if err := h.userService.LogoutAll(ctx, requesterID); err != nil {
			log.Println(err)
		}
	} else {
		if err := h.userService.Logout(ctx, requesterID, deviceID); err != nil {
			log.Println(err)
		}
	}

	http.SetCookie(w, &http.Cookie{
		Name:     h.cfg.JWT.CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // false только для localhost без https
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	w.WriteHeader(http.StatusNoContent)
}

func (h *UserHandler) Create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req dto.LRUUser
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		log.Println(err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	err = h.userService.Create(ctx, req.Login, req.Password)
	if err != nil {
		log.Println(err)
		errMsg, errCode := errs.MapError(err)
		http.Error(w, errMsg, errCode)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *UserHandler) UpdateLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requesterID := auth.GetUserID(ctx)

	var req dto.LRUUser
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		log.Println(err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	err = h.userService.UpdateLogin(ctx, requesterID, req.Login)
	if err != nil {
		log.Println(err)
		errMsg, errCode := errs.MapError(err)
		http.Error(w, errMsg, errCode)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *UserHandler) UpdatePassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requesterID := auth.GetUserID(ctx)

	var req dto.LRUUser
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		log.Println(err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	err = h.userService.UpdatePassword(r.Context(), requesterID, req.Password)
	if err != nil {
		log.Println(err)
		errMsg, errCode := errs.MapError(err)
		http.Error(w, errMsg, errCode)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *UserHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requesterID := auth.GetUserID(ctx)

	idStr := r.PathValue("id")
	ID, err := uuid.Parse(idStr)
	if err != nil {
		log.Println(err)
		http.Error(w, "Invalid request parameter 'id'", http.StatusBadRequest)
	}

	err = h.userService.Delete(r.Context(), ID, requesterID)
	if err != nil {
		log.Println(err)
		errMsg, errCode := errs.MapError(err)
		http.Error(w, errMsg, errCode)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
