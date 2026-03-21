CREATE TABLE users (
    id            UUID PRIMARY KEY,
    login         VARCHAR(20) NOT NULL,
    password_hash TEXT NOT NULL,

    CONSTRAINT users_login UNIQUE (login)
);

CREATE TABLE sessions (
    id        UUID PRIMARY KEY,
    user_id   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID NOT NULL,

    CONSTRAINT sessions_user_device UNIQUE (user_id, device_id)
);