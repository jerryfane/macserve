package controllerconfig

import "strings"

// Principal contains only a credential digest; plaintext tokens never enter SQLite.
type Principal struct {
	ID           string   `json:"id"`
	TokenSHA256  string   `json:"token_sha256"`
	Repositories []string `json:"repositories"`
	Scopes       []string `json:"scopes"`
	Revoked      bool     `json:"revoked"`
}

func (p Principal) HasScope(scope string) bool {
	if p.Revoked {
		return false
	}
	for _, value := range p.Scopes {
		if value == scope {
			return true
		}
	}
	return false
}

// AllowsRepository matches an exact "owner/name" entry or an account-level
// "owner/*" entry, which allows every repository of that GitHub account.
func (p Principal) AllowsRepository(repo string) bool {
	if p.Revoked {
		return false
	}
	owner, _, _ := strings.Cut(repo, "/")
	for _, value := range p.Repositories {
		if strings.EqualFold(value, repo) || strings.EqualFold(value, owner+"/*") && ValidRepository(repo) {
			return true
		}
	}
	return false
}

// AllowsOwner reports whether the principal may submit for some repository
// of a GitHub account: through an "owner/*" entry or an exact repository.
func (p Principal) AllowsOwner(owner string) bool {
	if p.Revoked {
		return false
	}
	for _, value := range p.Repositories {
		if entryOwner, _, _ := strings.Cut(value, "/"); strings.EqualFold(entryOwner, owner) {
			return true
		}
	}
	return false
}

// ValidOwnerWildcard accepts "owner/*" with a GitHub account login owner.
func ValidOwnerWildcard(entry string) bool {
	owner, ok := strings.CutSuffix(entry, "/*")
	return ok && ValidRepository(owner+"/x") && !strings.ContainsAny(owner, "_.")
}

// ValidRepository accepts an "owner/name" repository of bounded safe parts.
func ValidRepository(repo string) bool {
	owner, name, found := strings.Cut(repo, "/")
	if !found {
		return false
	}
	for _, part := range [2]string{owner, name} {
		if len(part) == 0 || len(part) > 100 || part == "." || part == ".." {
			return false
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
				return false
			}
		}
	}
	return true
}
