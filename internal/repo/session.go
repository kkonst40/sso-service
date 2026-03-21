package repo

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	errs "github.com/kkonst40/isso/internal/errors"
	"github.com/kkonst40/isso/internal/model"
)

type SessionRepo struct {
	db *sql.DB
}

func NewSessionRepo(db *sql.DB) *SessionRepo {
	return &SessionRepo{
		db: db,
	}
}

func (r *SessionRepo) Create(ctx context.Context, session *model.Session) error {
	const query = `
		INSERT INTO sessions (id, user_id, device_id)
		VALUES ($1, $2, $3)
	`

	_, err := r.db.ExecContext(ctx, query, session.ID, session.UserID, session.DeviceID)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == uniqueViolationCode {
				if pgErr.ConstraintName != "sessions_user_device" {
					return errs.ErrSessionExists
				}
			}
		}

		return fmt.Errorf("%w: %w", errs.ErrDatabase, err)
	}

	return nil
}

func (r *SessionRepo) Delete(ctx context.Context, userID, deviceID uuid.UUID) error {
	const query = `
		DELETE FROM sessions
		WHERE user_id = $1 AND device_id = $2
	`

	if _, err := r.db.ExecContext(ctx, query, userID, deviceID); err != nil {
		return fmt.Errorf("%w: %w", errs.ErrDatabase, err)
	}

	return nil
}

func (r *SessionRepo) DeleteAll(ctx context.Context, userID uuid.UUID) error {
	const query = `
		DELETE FROM sessions
		WHERE user_id = $1
	`

	if _, err := r.db.ExecContext(ctx, query, userID); err != nil {
		return fmt.Errorf("%w: %w", errs.ErrDatabase, err)
	}

	return nil
}
