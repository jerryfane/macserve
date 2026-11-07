package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/jerryfane/macserve/internal/controllerconfig"
)

var ErrUnauthenticated = errors.New("invalid bearer credential")

// ReplacePrincipals atomically replaces the complete configured credential set.
// Removed and explicitly revoked credentials cannot authenticate after reopening.
func (s *Store) ReplacePrincipals(ctx context.Context, principals []controllerconfig.Principal) error {
	normalized := make([]controllerconfig.Principal, len(principals))
	ids, digests := make(map[string]bool), make(map[string]bool)
	for i, p := range principals {
		digest, err := hex.DecodeString(p.TokenSHA256)
		if !validOpaque(p.ID, 256) || err != nil || len(digest) != sha256.Size || len(p.Repositories) > 1000 {
			return ErrInvalid
		}
		p.TokenSHA256 = strings.ToLower(p.TokenSHA256)
		if ids[p.ID] || digests[p.TokenSHA256] {
			return ErrInvalid
		}
		ids[p.ID], digests[p.TokenSHA256] = true, true
		p.Repositories = append([]string{}, p.Repositories...)
		for j, repo := range p.Repositories {
			repo = strings.ToLower(repo)
			if !controllerconfig.ValidRepository(repo) && !controllerconfig.ValidOwnerWildcard(repo) {
				return ErrInvalid
			}
			p.Repositories[j] = repo
		}
		p.Scopes = append([]string{}, p.Scopes...)
		for _, scope := range p.Scopes {
			switch scope {
			case "jobs:submit", "jobs:read", "jobs:cancel", "service:admin", "release:archive", "release:sign":
			default:
				return ErrInvalid
			}
		}
		normalized[i] = p
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS principals (id TEXT PRIMARY KEY,token_sha256 TEXT NOT NULL UNIQUE,repositories BLOB NOT NULL,scopes BLOB NOT NULL,revoked INTEGER NOT NULL)`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM principals"); err != nil {
		return err
	}
	for _, p := range normalized {
		repos, _ := json.Marshal(p.Repositories)
		scopes, _ := json.Marshal(p.Scopes)
		if _, err = tx.ExecContext(ctx, "INSERT INTO principals(id,token_sha256,repositories,scopes,revoked) VALUES(?,?,?,?,?)", p.ID, p.TokenSHA256, repos, scopes, p.Revoked); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) Authenticate(ctx context.Context, token string) (controllerconfig.Principal, error) {
	if len(token) < 32 || len(token) > 4096 || strings.IndexAny(token, " \t\r\n") >= 0 {
		return controllerconfig.Principal{}, ErrUnauthenticated
	}
	sum := sha256.Sum256([]byte(token))
	var p controllerconfig.Principal
	var repos, scopes []byte
	err := s.db.QueryRowContext(ctx, "SELECT id,token_sha256,repositories,scopes,revoked FROM principals WHERE token_sha256=?", hex.EncodeToString(sum[:])).Scan(&p.ID, &p.TokenSHA256, &repos, &scopes, &p.Revoked)
	if errors.Is(err, sql.ErrNoRows) || p.Revoked {
		return controllerconfig.Principal{}, ErrUnauthenticated
	}
	if err != nil {
		return controllerconfig.Principal{}, err
	}
	if err = json.Unmarshal(repos, &p.Repositories); err != nil {
		return controllerconfig.Principal{}, err
	}
	if err = json.Unmarshal(scopes, &p.Scopes); err != nil {
		return controllerconfig.Principal{}, err
	}
	return p, nil
}
