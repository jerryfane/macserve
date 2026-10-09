package deploy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jerryfane/macserve/internal/controller"
	"github.com/jerryfane/macserve/internal/maintenance"
	"github.com/jerryfane/macserve/internal/store"
	"github.com/jerryfane/macserve/internal/workerclient"
)

const Prefix = "/Library/macserve"

var assetNames = []string{"create-users.sh", "qualify.sh", "launchd/org.macserve.controller.plist.tmpl", "launchd/org.macserve.worker.plist.tmpl", "launchd/org.macserve.maintenance.plist.tmpl"}

type File struct {
	Path     string
	Data     []byte
	Mode     os.FileMode
	UID, GID uint32
}
type Material struct {
	Files                            []File
	Token                            string
	ReceiptPublicKey, TLSFingerprint string
}

// Render performs literal replacement only; unknown or stale markers are errors.
func Render(source []byte, values map[string]string) ([]byte, error) {
	s := string(source)
	for strings.Contains(s, "{{") {
		start := strings.Index(s, "{{")
		end := strings.Index(s[start:], "}}")
		if end < 0 {
			return nil, errors.New("unterminated template marker")
		}
		end += start + 2
		marker := s[start:end]
		v, ok := values[marker]
		if !ok || strings.ContainsAny(v, "{}") {
			return nil, fmt.Errorf("unknown template marker %q", marker)
		}
		s = s[:start] + v + s[end:]
	}
	if strings.Contains(s, "}}") || strings.Contains(s, "{{") {
		return nil, errors.New("unresolved template marker")
	}
	return []byte(s), nil
}
func renderAssets(e Environment, assets map[string][]byte) (map[string][]byte, error) {
	values := map[string]string{"{{.ControllerUser}}": e.ControllerUser, "{{.ControllerGroup}}": e.ControllerUser, "{{.JobUID}}": strconv.FormatUint(uint64(e.JobUID), 10)}
	result := map[string][]byte{}
	for _, name := range assetNames[2:] {
		source, ok := assets[name]
		if !ok {
			return nil, fmt.Errorf("missing asset %s", name)
		}
		rendered, err := Render(source, values)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if strings.HasPrefix(name, "launchd/") {
			if err := disabledPlist(rendered); err != nil {
				return nil, err
			}
		}
		result[name] = rendered
	}
	return result, nil
}
func disabledPlist(data []byte) error {
	d := xml.NewDecoder(bytes.NewReader(data))
	disabled, runAtLoad := 0, 0
	for {
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "key" {
			continue
		}
		var key string
		if err := d.DecodeElement(&key, &start); err != nil {
			return err
		}
		if key != "Disabled" && key != "RunAtLoad" {
			continue
		}
		for {
			token, err = d.Token()
			if err != nil {
				return err
			}
			if text, ok := token.(xml.CharData); ok && strings.TrimSpace(string(text)) == "" {
				continue
			}
			break
		}
		value, ok := token.(xml.StartElement)
		if !ok {
			return errors.New("invalid launchd activation flag")
		}
		if key == "Disabled" {
			disabled++
			if value.Name.Local != "true" {
				return errors.New("launchd must remain disabled")
			}
		} else {
			runAtLoad++
			if value.Name.Local != "false" {
				return errors.New("launchd must not run at load")
			}
		}
	}
	if disabled != 1 || runAtLoad != 1 {
		return errors.New("launchd requires unique Disabled=true and RunAtLoad=false")
	}
	return nil
}
func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func opaque() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
func privatePEM(key ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// makeMaterial produces file intents separately from native writes. The bearer
// token is deliberately not a member of any persisted file or manifest.
func makeMaterial(e Environment, envData []byte, rendered map[string][]byte, now time.Time) (Material, error) {
	var m Material
	token, err := opaque()
	if err != nil {
		return m, err
	}
	m.Token = token
	keyID, err := opaque()
	if err != nil {
		return m, err
	}
	serviceID, err := opaque()
	if err != nil {
		return m, err
	}
	hostID, err := opaque()
	if err != nil {
		return m, err
	}
	pub, receiptKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return m, err
	}
	m.ReceiptPublicKey = base64.StdEncoding.EncodeToString(pub)
	_, tlsKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return m, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return m, err
	}
	serial.Add(serial, big.NewInt(1))
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "macserve private API"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IPAddresses: []net.IP{net.ParseIP(e.TailnetIP)}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, tlsKey.Public(), tlsKey)
	if err != nil {
		return m, err
	}
	m.TLSFingerprint = digest(der)
	tlsPEM, err := privatePEM(tlsKey)
	if err != nil {
		return m, err
	}
	receiptPEM, err := privatePEM(receiptKey)
	if err != nil {
		return m, err
	}
	add := func(path string, data []byte, mode os.FileMode, uid, gid uint32) {
		m.Files = append(m.Files, File{path, data, mode, uid, gid})
	}
	jsonFile := func(path string, value any) error {
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return err
		}
		add(path, append(data, '\n'), 0644, 0, 0)
		return nil
	}
	secrets := Prefix + "/var/controller/secrets/"
	add(secrets+"tls-key.pem", tlsPEM, 0600, e.ControllerUID, e.ControllerGID)
	add(secrets+"receipt-key.pem", receiptPEM, 0600, e.ControllerUID, e.ControllerGID)
	add(Prefix+"/config/tls-cert.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644, 0, 0)
	add(Prefix+"/config/deploy.env", envData, 0644, 0, 0)
	add(Prefix+"/config/profiles.json", []byte("{\"profiles\":[]}\n"), 0644, 0, 0)
	for _, service := range []string{"controller", "worker", "maintenance"} {
		name := "org.macserve." + service + ".plist"
		add("/Library/LaunchDaemons/"+name, rendered["launchd/"+name+".tmpl"], 0644, 0, 0)
	}
	repos := make([]string, 0, len(e.Repositories))
	for repo := range e.Repositories {
		repos = append(repos, repo)
	}
	sort.Strings(repos)
	c := controller.Config{Root: Prefix + "/var/controller", Socket: Prefix + "/var/controller/run/worker.sock", JobUID: e.JobUID, ProfilesFile: Prefix + "/config/profiles.json", Listen: netip.AddrPortFrom(netip.MustParseAddr(e.TailnetIP), e.Port).String(), AllowedNetworks: []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48"}, TLSCertificate: Prefix + "/config/tls-cert.pem", TLSKey: secrets + "tls-key.pem", Principals: []store.Principal{{ID: "owner", TokenSHA256: digest([]byte(token)), Repositories: repos, Scopes: []string{"jobs:submit", "jobs:read", "jobs:cancel", "service:admin"}}}, HealthFile: Prefix + "/health/current.json", PauseFile: Prefix + "/config/owner.pause", OwnerUID: e.OwnerUID, Receipt: controller.ReceiptConfig{KeyID: keyID, PrivateKeyFile: secrets + "receipt-key.pem", ServiceID: serviceID, HostID: hostID, Repositories: e.Repositories, VerificationKeys: map[string]string{keyID: m.ReceiptPublicKey}}}
	w := workerclient.Config{Socket: c.Socket, ControllerUID: e.ControllerUID, Root: Prefix + "/var/broker", ExportRoot: Prefix + "/var/exports", WorkspaceRoot: Prefix + "/var/workspaces", JobUID: e.JobUID, JobGID: e.JobGID, OwnerUID: e.OwnerUID, HelperPath: Prefix + "/bin/macserve", BaselinePath: Prefix + "/var/broker/gui-baseline.json", PollSeconds: 2, HeartbeatSeconds: 5, RequestTimeoutSeconds: 10}
	maintenanceConfig := maintenance.Config{ControllerConfig: Prefix + "/config/controller.json", WorkerConfig: Prefix + "/config/worker.json", QualificationFile: Prefix + "/config/qualification.json", BoundaryEvidenceFile: Prefix + "/config/boundary-evidence.json", CoexistingAnchors: e.CoexistingAnchors, CoexistingServices: e.CoexistingServices, IntervalSeconds: 10}
	for _, item := range []struct {
		name  string
		value any
	}{{"controller.json", c}, {"worker.json", w}, {"maintenance.json", maintenanceConfig}, {"deployment-pins.json", map[string]string{"receipt_key_id": keyID, "receipt_public_key": m.ReceiptPublicKey, "tls_certificate_sha256": m.TLSFingerprint, "service_id": serviceID, "host_id": hostID}}} {
		if err := jsonFile(Prefix+"/config/"+item.name, item.value); err != nil {
			return m, err
		}
	}
	add(Prefix+"/config/owner.pause", []byte("Deployment pending owner qualification; services remain disabled.\n"), 0644, 0, 0)
	return m, nil
}
