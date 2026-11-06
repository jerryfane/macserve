package signer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/jerryfane/macserve/internal/receipt"
)

// InitResult is what signer-init prints for the controller configuration.
type InitResult struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

// Init creates, as the signer account and only where absent, the signer
// receipt key (PKCS#8 PEM, 0600), the keychain secret (0600) and the empty
// signer keychain, each in a 0700 directory, and returns the receipt key's
// public half. Existing files are kept, so Init is safe to repeat.
func Init(ctx context.Context, c Config, tools Tools) (InitResult, error) {
	for _, dir := range []string{filepath.Dir(c.KeyFile), filepath.Dir(c.Keychain), filepath.Dir(c.KeychainSecretFile)} {
		if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return InitResult{}, err
		}
		if err := privateDir(dir); err != nil {
			return InitResult{}, err
		}
	}
	if _, err := os.Lstat(c.KeyFile); errors.Is(err, fs.ErrNotExist) {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return InitResult{}, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return InitResult{}, err
		}
		if err := createPrivate(c.KeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
			return InitResult{}, err
		}
	} else if err != nil {
		return InitResult{}, err
	}
	if _, err := os.Lstat(c.KeychainSecretFile); errors.Is(err, fs.ErrNotExist) {
		var random [32]byte
		if _, err := rand.Read(random[:]); err != nil {
			return InitResult{}, err
		}
		if err := createPrivate(c.KeychainSecretFile, []byte(fmt.Sprintf("%x\n", random))); err != nil {
			return InitResult{}, err
		}
	} else if err != nil {
		return InitResult{}, err
	}
	secret, err := ReadSecret(c.KeychainSecretFile)
	if err != nil {
		return InitResult{}, err
	}
	if _, err := os.Lstat(c.Keychain); errors.Is(err, fs.ErrNotExist) {
		if err := tools.CreateKeychain(ctx, c.Keychain, secret); err != nil {
			return InitResult{}, err
		}
	} else if err != nil {
		return InitResult{}, err
	}
	if err := privateFile(c.Keychain); err != nil {
		return InitResult{}, err
	}
	key, err := ReadKey(c.KeyFile)
	if err != nil {
		return InitResult{}, err
	}
	return InitResult{KeyID: c.KeyID, PublicKey: base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}, nil
}

// ReadKey reads the signer receipt key from its 0600 file.
func ReadKey(path string) (ed25519.PrivateKey, error) {
	if err := privateFile(path); err != nil {
		return nil, err
	}
	raw, err := readInput(path, 64<<10)
	if err != nil {
		return nil, err
	}
	return receipt.ParsePrivateKey(raw)
}

// ReadSecret reads the keychain secret from its 0600 file.
func ReadSecret(path string) (string, error) {
	if err := privateFile(path); err != nil {
		return "", err
	}
	raw, err := readInput(path, 1024)
	if err != nil {
		return "", err
	}
	secret := strings.TrimSuffix(string(raw), "\n")
	if !keychainSecretPattern.MatchString(secret) {
		return "", errors.New("keychain secret must be 32-128 ASCII letters and digits")
	}
	return secret, nil
}

func createPrivate(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|noFollow, 0o600)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	if err == nil {
		err = file.Sync()
	}
	return errors.Join(err, file.Close())
}

// privateFile requires a regular file owned by this account, mode 0600 or
// stricter.
func privateFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !ownedByMe(info) {
		return fmt.Errorf("%s must be a regular file owned by the signer, mode 0600", path)
	}
	return nil
}

// privateDir requires a directory owned by this account, mode 0700.
func privateDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 || !ownedByMe(info) {
		return fmt.Errorf("%s must be a directory owned by the signer, mode 0700", path)
	}
	return nil
}
