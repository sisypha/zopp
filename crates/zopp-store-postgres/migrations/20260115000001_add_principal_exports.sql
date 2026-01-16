-- Principal exports table for multi-device support
-- Stores encrypted principal data that can be transferred to new devices

CREATE TABLE principal_exports (
    id UUID PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,       -- SHA256(secret), used for lookup (UNIQUE creates implicit index)
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    principal_id UUID NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    encrypted_data BYTEA NOT NULL,         -- Encrypted principal JSON (passphrase-derived key)
    salt BYTEA NOT NULL,                   -- Argon2id salt for key derivation
    nonce BYTEA NOT NULL,                  -- XChaCha20-Poly1305 nonce
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consumed BOOLEAN NOT NULL DEFAULT FALSE
);

-- Note: token_hash index not needed - UNIQUE constraint creates implicit index
CREATE INDEX idx_principal_exports_user_id ON principal_exports(user_id);
CREATE INDEX idx_principal_exports_expires_at ON principal_exports(expires_at);
