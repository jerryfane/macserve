package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jerryfane/macserve/internal/store"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// Config is root-controlled policy. It contains token digests, never bearer tokens.
type Config struct {
	Root            string            `json:"root"`
	Socket          string            `json:"socket"`
	JobUID          uint32            `json:"job_uid"`
	ProfilesFile    string            `json:"profiles_file"`
	Listen          string            `json:"listen"`
	AllowedNetworks []string          `json:"allowed_networks"`
	TLSCertificate  string            `json:"tls_certificate"`
	TLSKey          string            `json:"tls_key"`
	Principals      []store.Principal `json:"principals"`
	HealthFile      string            `json:"health_file"`
	PolicySHA256    string            `json:"policy_sha256"`
	PauseFile       string            `json:"pause_file,omitempty"`
	OwnerUID        uint32            `json:"owner_uid"`
}

func LoadConfig(path string) (Config, error) {
	var c Config
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return c, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return c, errors.New("controller configuration must be a bounded regular file")
	}
	d := json.NewDecoder(io.LimitReader(f, (1<<20)+1))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, err
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return c, errors.New("trailing controller configuration")
	}
	if err = c.validate(); err != nil {
		return c, err
	}
	return c, nil
}
func cleanAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && !strings.ContainsRune(path, 0)
}
func (c *Config) validate() error {
	for _, path := range []string{c.Root, c.Socket, c.ProfilesFile, c.TLSCertificate, c.TLSKey, c.HealthFile} {
		if !cleanAbsolute(path) {
			return errors.New("controller paths must be clean absolute paths")
		}
	}
	if c.JobUID < 501 || c.OwnerUID == 0 || c.JobUID == c.OwnerUID {
		return errors.New("job UID must be a dedicated login UID distinct from the non-root owner")
	}
	if !digestString(c.PolicySHA256) {
		return errors.New("invalid network policy digest")
	}
	if c.PauseFile != "" && !cleanAbsolute(c.PauseFile) {
		return errors.New("invalid owner pause path")
	}
	address, err := netip.ParseAddrPort(c.Listen)
	if err != nil || address.Port() == 0 {
		return errors.New("listener must be a literal private IP and nonzero port")
	}
	ip := address.Addr()
	if ip.Is4In6() || ip.Zone() != "" || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return errors.New("unsafe listener address")
	}
	if len(c.AllowedNetworks) == 0 {
		c.AllowedNetworks = []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48"}
	}
	allowed := false
	for _, text := range c.AllowedNetworks {
		p, e := netip.ParsePrefix(text)
		if e != nil || p != p.Masked() {
			return errors.New("invalid listener network")
		}
		if !privatePrefix(p) {
			return fmt.Errorf("listener network is outside tailnet ranges: %s", text)
		}
		allowed = allowed || p.Contains(ip)
	}
	if !allowed {
		return errors.New("listener address is outside configured private networks")
	}
	return nil
}
func privatePrefix(p netip.Prefix) bool {
	for _, text := range []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48"} {
		b := netip.MustParsePrefix(text)
		if p.Addr().BitLen() == b.Addr().BitLen() && p.Bits() >= b.Bits() && b.Contains(p.Addr()) {
			return true
		}
	}
	return false
}
