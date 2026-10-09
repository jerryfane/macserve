package hostguard

import (
	"errors"
	"os/user"
	"testing"
)

func TestNativeJobPrimaryGroupIsDedicated(t *testing.T) {
	for _, tc := range []struct {
		name                                     string
		jobGID                                   uint32
		primary                                  string
		ownerPrimary, controllerPrimary          string
		jobGroups, ownerGroups, controllerGroups []string
		missingOwner, groupFailure               bool
		wantError                                bool
	}{
		{name: "dedicated primary", jobGID: 502, primary: "502", jobGroups: []string{"502"}},
		{name: "supplementary staff", jobGID: 502, primary: "502", jobGroups: []string{"502", "20"}, wantError: true},
		{name: "stock staff primary", jobGID: 20, primary: "20", wantError: true},
		{name: "mismatched configured primary", jobGID: 502, primary: "504", wantError: true},
		{name: "owner shared primary", jobGID: 502, primary: "502", ownerPrimary: "502", wantError: true},
		{name: "controller shared primary", jobGID: 502, primary: "502", controllerPrimary: "502", wantError: true},
		{name: "owner supplementary membership", jobGID: 502, primary: "502", ownerGroups: []string{"20", "502"}, wantError: true},
		{name: "controller supplementary membership", jobGID: 502, primary: "502", controllerGroups: []string{"503", "502"}, wantError: true},
		{name: "admin primary", jobGID: 80, primary: "80", wantError: true},
		{name: "admin supplementary", jobGID: 502, primary: "502", jobGroups: []string{"502", "80"}, wantError: true},
		{name: "root supplementary", jobGID: 502, primary: "502", jobGroups: []string{"502", "0"}, wantError: true},
		{name: "missing owner fails closed", jobGID: 502, primary: "502", missingOwner: true, wantError: true},
		{name: "unresolved memberships fail closed", jobGID: 502, primary: "502", groupFailure: true, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ownerPrimary, controllerPrimary := tc.ownerPrimary, tc.controllerPrimary
			if ownerPrimary == "" {
				ownerPrimary = "20"
			}
			if controllerPrimary == "" {
				controllerPrimary = "503"
			}
			accounts := map[string]*user.User{
				"501": {Uid: "501", Gid: ownerPrimary},
				"502": {Uid: "502", Gid: tc.primary},
				"503": {Uid: "503", Gid: controllerPrimary},
			}
			if tc.missingOwner {
				delete(accounts, "501")
			}
			lookup := func(uid string) (*user.User, error) {
				account, ok := accounts[uid]
				if !ok {
					return nil, errors.New("unknown identity")
				}
				return account, nil
			}
			lookupGroup := func(name string) (*user.Group, error) {
				if name != "admin" {
					return nil, errors.New("unknown group")
				}
				return &user.Group{Gid: "80", Name: "admin"}, nil
			}
			groups := func(account *user.User) ([]string, error) {
				if tc.groupFailure {
					return nil, errors.New("membership unavailable")
				}
				switch account.Uid {
				case "501":
					return tc.ownerGroups, nil
				case "502":
					return tc.jobGroups, nil
				default:
					return tc.controllerGroups, nil
				}
			}
			account, err := nativeJobIdentity(502, tc.jobGID, 503, 501, lookup, lookupGroup, groups)
			if (err != nil) != tc.wantError {
				t.Fatalf("identity error = %v, wantError = %v", err, tc.wantError)
			}
			if err == nil && account.Uid != "502" {
				t.Fatalf("resolved unexpected job account %v", account)
			}
		})
	}
}
