package signer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
)

// Entitlement keys the profile derives rather than the build requests.
const (
	appIdentifierKey  = "application-identifier"
	teamIdentifierKey = "com.apple.developer.team-identifier"
	keychainGroupsKey = "keychain-access-groups"
	getTaskAllowKey   = "get-task-allow"
	apsEnvironmentKey = "aps-environment"
)

// finalEntitlements returns the entitlements to sign a bundle with: every
// requested key, each present in the profile and allowed by its value, plus
// the profile-derived application-identifier, team-identifier,
// get-task-allow (false) and keychain-access-groups (the bundle's own
// <team>.<bundle id> group from the profile's wildcard when the build
// requested none). Requested values may use $(AppIdentifierPrefix) and
// $(TeamIdentifierPrefix), which resolve to "<team>.". A requested key the
// profile lacks, a value it does not allow, a malformed value or a missing
// required key refuses the bundle.
func finalEntitlements(requested json.RawMessage, profile Profile, required []string) (map[string]any, error) {
	refuse := func(format string, args ...any) (map[string]any, error) {
		return nil, fmt.Errorf("entitlements for %s: "+format, append([]any{profile.BundleID}, args...)...)
	}
	decoder := json.NewDecoder(bytes.NewReader(requested))
	decoder.UseNumber()
	var raw map[string]any
	if err := decoder.Decode(&raw); err != nil || raw == nil || decoder.More() {
		return refuse("requested entitlements are not a JSON object")
	}
	converted, err := jsonToPlist(raw)
	if err != nil {
		return refuse("%v", err)
	}
	prefix := profile.TeamID + "."
	resolved, err := resolveMacros(converted, prefix)
	if err != nil {
		return refuse("%v", err)
	}
	request := resolved.(map[string]any)
	allowed := profile.Entitlements
	appID := profile.TeamID + "." + profile.BundleID
	final := map[string]any{appIdentifierKey: appID, teamIdentifierKey: profile.TeamID}
	if _, found := allowed[getTaskAllowKey]; found {
		final[getTaskAllowKey] = false
	}
	keys := make([]string, 0, len(request))
	for key := range request {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		value := request[key]
		switch key {
		case appIdentifierKey, teamIdentifierKey:
			// Identity comes from the profile; a build's value must at
			// least be a string naming this bundle or team.
			s, ok := value.(string)
			if !ok || key == appIdentifierKey && !strings.HasSuffix(s, profile.BundleID) || key == teamIdentifierKey && s != profile.TeamID && s != "" {
				return refuse("requested %s %v contradicts the profile", key, value)
			}
			continue
		}
		permitted, found := allowed[key]
		if !found {
			return refuse("requested %s is not in the profile", key)
		}
		value, err := permit(key, value, permitted)
		if err != nil {
			return refuse("%v", err)
		}
		final[key] = value
	}
	if _, found := final[keychainGroupsKey]; !found {
		if patterns, ok := allowed[keychainGroupsKey].([]any); ok && matchesAny(patterns, appID) {
			final[keychainGroupsKey] = []any{appID}
		}
	}
	for _, key := range required {
		if _, found := final[key]; !found {
			return refuse("required %s is missing", key)
		}
	}
	return final, nil
}

// permit checks one requested value against the profile's value for key
// and returns the value to sign.
func permit(key string, value, profile any) (any, error) {
	if key == apsEnvironmentKey {
		// Builds request development; distribution signs the profile's.
		s, ok := value.(string)
		if !ok || s != "development" && s != "production" {
			return nil, fmt.Errorf("aps-environment %v is malformed", value)
		}
		if _, ok := profile.(string); !ok {
			return nil, fmt.Errorf("profile aps-environment is malformed")
		}
		return profile, nil
	}
	switch p := profile.(type) {
	case bool:
		v, ok := value.(bool)
		if !ok || v && !p {
			return nil, fmt.Errorf("requested %s %v is not allowed by the profile's %v", key, value, p)
		}
		return v, nil
	case string:
		// A profile string allows an equal string, or (as "*" or a
		// trailing-* prefix) any matching string or list of strings.
		if v, ok := value.(string); ok {
			if !wildcardMatch(p, v) {
				return nil, fmt.Errorf("requested %s %q is not allowed by the profile's %q", key, v, p)
			}
			return v, nil
		}
		if _, ok := value.([]any); ok && strings.HasSuffix(p, "*") {
			return permit(key, value, []any{p})
		}
		return nil, fmt.Errorf("requested %s %v is malformed for the profile's %q", key, value, p)
	case []any:
		switch v := value.(type) {
		case string:
			if !matchesAny(p, v) {
				return nil, fmt.Errorf("requested %s %q is not allowed by the profile", key, v)
			}
			return v, nil
		case []any:
			seen := map[string]bool{}
			for _, item := range v {
				s, ok := item.(string)
				if !ok || s == "" || seen[s] {
					return nil, fmt.Errorf("requested %s has a malformed or duplicate entry", key)
				}
				seen[s] = true
				if !matchesAny(p, s) {
					return nil, fmt.Errorf("requested %s entry %q is not allowed by the profile", key, s)
				}
			}
			return v, nil
		}
		return nil, fmt.Errorf("requested %s %v is malformed", key, value)
	}
	if !reflect.DeepEqual(value, profile) {
		return nil, fmt.Errorf("requested %s differs from the profile", key)
	}
	return value, nil
}

// wildcardMatch reports whether a profile value allows s: equal, or a
// trailing-* prefix ("TEAM.*", "*").
func wildcardMatch(pattern, s string) bool {
	if prefix, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(s, prefix) && s != prefix
	}
	return pattern == s
}

func matchesAny(patterns []any, s string) bool {
	for _, item := range patterns {
		if pattern, ok := item.(string); ok && wildcardMatch(pattern, s) {
			return true
		}
	}
	return false
}

// resolveMacros substitutes the team prefix macros in every string and
// refuses any other $( build setting reference.
func resolveMacros(value any, prefix string) (any, error) {
	switch v := value.(type) {
	case string:
		s := strings.ReplaceAll(strings.ReplaceAll(v, "$(AppIdentifierPrefix)", prefix), "$(TeamIdentifierPrefix)", prefix)
		if strings.Contains(s, "$(") || strings.Contains(s, "${") {
			return nil, fmt.Errorf("unresolved build setting in %q", v)
		}
		return s, nil
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			resolved, err := resolveMacros(item, prefix)
			if err != nil {
				return nil, err
			}
			out[i] = resolved
		}
		return out, nil
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			resolved, err := resolveMacros(item, prefix)
			if err != nil {
				return nil, err
			}
			out[key] = resolved
		}
		return out, nil
	}
	return value, nil
}
