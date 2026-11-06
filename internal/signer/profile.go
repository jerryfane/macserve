package signer

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"
)

// maxProfileBytes bounds a provisioning profile file.
const maxProfileBytes = 1 << 20

// Profile is a validated App Store distribution provisioning profile.
type Profile struct {
	// Raw is the exact CMS file bytes embedded into the bundle.
	Raw          []byte
	SHA256       string
	UUID         string
	Name         string
	TeamID       string
	BundleID     string
	Expiration   time.Time
	Entitlements map[string]any
}

// parseProfile validates a decoded profile plist for bundleID: App Store
// distribution (no ProvisionedDevices, no ProvisionsAllDevices, the
// beta-reports-active marker App Store profiles carry), the iOS platform,
// unexpired at now, exactly teamID, application-identifier exactly
// <teamID>.<bundleID> (no wildcard App ID), get-task-allow false, and the
// identity's certificate (by SHA-1 of its DER) among DeveloperCertificates.
func parseProfile(raw, decoded []byte, bundleID, teamID, identitySHA1 string, now time.Time) (Profile, error) {
	refuse := func(format string, args ...any) (Profile, error) {
		return Profile{}, fmt.Errorf("profile for %s: "+format, append([]any{bundleID}, args...)...)
	}
	value, err := decodePlist(decoded)
	if err != nil {
		return refuse("%v", err)
	}
	dict, ok := value.(map[string]any)
	if !ok {
		return refuse("is not a dictionary")
	}
	if _, found := dict["ProvisionedDevices"]; found {
		return refuse("lists ProvisionedDevices (development or ad hoc, not App Store)")
	}
	if _, found := dict["ProvisionsAllDevices"]; found {
		return refuse("has ProvisionsAllDevices (enterprise, not App Store)")
	}
	uuid, _ := dict["UUID"].(string)
	if !validUUID(uuid) {
		return refuse("UUID %q", uuid)
	}
	name, _ := dict["Name"].(string)
	platforms, _ := dict["Platform"].([]any)
	if !slices.Contains(platforms, any("iOS")) {
		return refuse("is not for the iOS platform")
	}
	expiration, ok := dict["ExpirationDate"].(time.Time)
	if !ok || !now.Before(expiration) {
		return refuse("expired or has no ExpirationDate")
	}
	if created, ok := dict["CreationDate"].(time.Time); ok && now.Before(created) {
		return refuse("is not yet valid")
	}
	teams, _ := dict["TeamIdentifier"].([]any)
	if len(teams) != 1 || teams[0] != any(teamID) {
		return refuse("TeamIdentifier %v is not exactly %s", teams, teamID)
	}
	entitlements, ok := dict["Entitlements"].(map[string]any)
	if !ok {
		return refuse("has no Entitlements dictionary")
	}
	if entitlements["com.apple.developer.team-identifier"] != any(teamID) {
		return refuse("team-identifier entitlement is not %s", teamID)
	}
	if appID := entitlements["application-identifier"]; appID != any(teamID+"."+bundleID) {
		return refuse("application-identifier %v is not %s.%s", appID, teamID, bundleID)
	}
	if allow, found := entitlements["get-task-allow"]; found && allow != any(false) {
		return refuse("get-task-allow is not false")
	}
	if entitlements["beta-reports-active"] != any(true) {
		return refuse("lacks the App Store beta-reports-active marker")
	}
	certificates, _ := dict["DeveloperCertificates"].([]any)
	found := false
	for _, item := range certificates {
		der, ok := item.([]byte)
		if !ok {
			return refuse("DeveloperCertificates has a non-data entry")
		}
		sum := sha1.Sum(der)
		found = found || strings.EqualFold(hex.EncodeToString(sum[:]), identitySHA1)
	}
	if !found {
		return refuse("does not include the configured distribution certificate %s", identitySHA1)
	}
	digest := sha256.Sum256(raw)
	return Profile{Raw: raw, SHA256: hex.EncodeToString(digest[:]), UUID: uuid, Name: name, TeamID: teamID, BundleID: bundleID, Expiration: expiration, Entitlements: entitlements}, nil
}

func validUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}
