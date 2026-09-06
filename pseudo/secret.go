package pseudo

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
)

// DefaultSecretFile is the file name used when salt_secret_path is empty.
// The name is deliberate: the local guard hook on the development machine
// blocks commands containing "key_file" or the extension ".key".
const DefaultSecretFile = "pseudonym.secret"

// MinSecretLen is the smallest number of bytes accepted after trimming.
const MinSecretLen = 32

// ErrSecretTooShort is returned when fewer than MinSecretLen bytes remain
// after trimming. The plugin then refuses to start in pseudonymize mode.
var ErrSecretTooShort = errors.New("pseudo: secret shorter than 32 bytes")

// ResolveSecretPath returns the absolute path of the secret file. An empty
// configured value means DefaultSecretFile; a relative value is resolved
// against pluginDir, the directory of the shared object, like gitleaks_toml
// in the original plugin. An absolute value is returned unchanged.
func ResolveSecretPath(pluginDir, configured string) string {
	if configured == "" {
		configured = DefaultSecretFile
	}
	if filepath.IsAbs(configured) {
		return configured
	}
	return filepath.Join(pluginDir, configured)
}

// LoadSecret reads the file at path, trims leading and trailing white space
// (the file on the target host holds 64 hex characters and a newline) and
// returns the remaining bytes unchanged as the HMAC key; there is no hex
// decoding. It returns ErrSecretTooShort when fewer than MinSecretLen bytes
// remain and the read error when the file cannot be opened. The contents
// are never logged.
func LoadSecret(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	secret := bytes.TrimSpace(raw)
	if len(secret) < MinSecretLen {
		return nil, ErrSecretTooShort
	}
	return secret, nil
}
