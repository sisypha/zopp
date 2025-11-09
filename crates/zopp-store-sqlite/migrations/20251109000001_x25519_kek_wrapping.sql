-- Add X25519 public keys to principals for encryption (ECDH)
ALTER TABLE principals ADD COLUMN x25519_public_key BLOB;

-- Add KEK wrapping fields to existing workspace_principals table
ALTER TABLE workspace_principals ADD COLUMN ephemeral_pub BLOB NOT NULL DEFAULT X'';
ALTER TABLE workspace_principals ADD COLUMN kek_wrapped BLOB NOT NULL DEFAULT X'';
ALTER TABLE workspace_principals ADD COLUMN kek_nonce BLOB NOT NULL DEFAULT X'';

-- Add encrypted KEK to invites (encrypted with invite_secret, NOT stored in DB)
ALTER TABLE invites ADD COLUMN kek_encrypted BLOB;
ALTER TABLE invites ADD COLUMN kek_nonce BLOB;
