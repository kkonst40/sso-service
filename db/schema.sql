-- schema.sql

CREATE TABLE users (
    id            UUID PRIMARY KEY,
    login         VARCHAR(20) NOT NULL,
    password_hash TEXT NOT NULL,
    token_id      UUID NOT NULL,

    CONSTRAINT users_login_key UNIQUE (login)
);