package worker

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jerryfane/macserve/internal/hostguard"
)

func ownedLabel(identifier string) string {
	switch identifier {
	case "16.org.macserve.controller", "16.org.macserve.worker", "16.org.macserve.maintenance":
		return strings.TrimPrefix(identifier, "16.")
	}
	return ""
}

// These are structural constraints, not trust in a label. Live protected-file
// and running-executable checks are mandatory before removing a container.
func ownedServiceMetadata(r BTMRecord, helper string) error {
	f := r.Fields
	label := ownedLabel(f["Identifier"])
	if label == "" || f["Type"] != "legacy daemon (0x10010)" || f["Flags"] != "[ legacy ] (0x1)" ||
		f["URL"] != "/Library/LaunchDaemons/"+label+".plist" || f["Executable Path"] != helper ||
		!filepath.IsAbs(helper) || filepath.Clean(helper) != helper ||
		f["Bundle Identifier"] != "" || f["Team Identifier"] != "" || len(r.Embedded) != 0 {
		return errors.New("owned service registration binding mismatch")
	}
	return nil
}

// Resolve only exact referenced owned identifiers from UID -2. Unrelated root
// records are not authority and are never copied into the review manifest.
func ownedReferences(output string, census BTMCensus) ([]BTMRecord, error) {
	wanted := map[string]bool{}
	for _, r := range census.Records {
		if r.Fields["Type"] == "developer (0x20)" {
			for _, id := range r.Embedded {
				if ownedLabel(id) != "" {
					wanted[id] = true
				}
			}
		}
	}
	if len(wanted) == 0 {
		return nil, nil
	}
	var result []BTMRecord
	var lines []string
	root, seenRoot := false, false
	seen := map[string]bool{}
	flush := func() error {
		if len(lines) == 0 {
			return nil
		}
		matches := false
		for _, line := range lines {
			key, value, _ := strings.Cut(line, ": ")
			if key == "Identifier" && wanted[value] {
				matches = true
			}
		}
		if !matches {
			return nil
		}
		r := BTMRecord{Fields: map[string]string{}}
		for _, line := range lines {
			key, value, ok := strings.Cut(line, ": ")
			if !ok || value == "" || r.Fields[key] != "" {
				return errors.New("ambiguous owned service record")
			}
			switch key {
			case "UUID", "Name", "Developer Name", "Team Identifier", "Type", "Flags", "Disposition", "Identifier", "URL", "Generation", "Bundle Identifier", "Parent Identifier", "Executable Path":
				r.Fields[key] = value
			default:
				return errors.New("unsupported owned service record field")
			}
		}
		for _, key := range []string{"UUID", "Name", "Developer Name", "Type", "Flags", "Disposition", "Identifier", "URL", "Generation", "Executable Path", "Parent Identifier"} {
			if r.Fields[key] == "" {
				return errors.New("incomplete owned service record")
			}
		}
		if !btmUUID.MatchString(r.Fields["UUID"]) || seen[r.Fields["Identifier"]] || seen["uuid:"+r.Fields["UUID"]] {
			return errors.New("duplicate or invalid owned service record")
		}
		if _, err := strconv.ParseUint(r.Fields["Generation"], 10, 64); err != nil {
			return errors.New("invalid owned service generation")
		}
		seen["uuid:"+r.Fields["UUID"]] = true
		seen[r.Fields["Identifier"]] = true
		result = append(result, r)
		return nil
	}
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "Records for UID") {
			if err := flush(); err != nil {
				return nil, err
			}
			lines = nil
			header := btmHeader.FindStringSubmatch(line)
			if header == nil {
				return nil, errors.New("ambiguous background UID section")
			}
			root = header[1] == "-2"
			if root {
				if seenRoot {
					return nil, errors.New("duplicate root background section")
				}
				seenRoot = true
			}
			continue
		}
		if !root {
			continue
		}
		if btmRecordHeader.MatchString(line) {
			if err := flush(); err != nil {
				return nil, err
			}
			lines = []string{}
			continue
		}
		if lines != nil && line != "" {
			lines = append(lines, line)
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return result, nil
}

func ownContainer(r BTMRecord, services []BTMRecord) (bool, error) {
	if r.Fields["Type"] != "developer (0x20)" {
		return false, nil
	}
	owned := false
	for _, id := range r.Embedded {
		owned = owned || ownedLabel(id) != ""
	}
	if !owned {
		return false, nil
	}
	if r.Fields["URL"] != "(null)" || r.Fields["Parent Identifier"] != "" || r.Fields["Bundle Identifier"] != "" || r.Fields["Flags"] != "[  ] (0)" || r.Fields["Disposition"] != "[disabled, allowed, notified] (0xa)" {
		return false, errors.New("unsupported own-service notification container")
	}
	seen := map[string]bool{}
	for _, id := range r.Embedded {
		if ownedLabel(id) == "" || seen[id] {
			return false, errors.New("mixed or duplicate own-service reference")
		}
		seen[id] = true
		found := false
		for _, service := range services {
			if service.Fields["Identifier"] != id {
				continue
			}
			if found || service.Fields["Parent Identifier"] != r.Fields["Identifier"] || ownedServiceMetadata(service, service.Fields["Executable Path"]) != nil {
				return false, errors.New("own-service reference binding mismatch")
			}
			found = true
		}
		if !found {
			return false, errors.New("unresolved own-service reference")
		}
	}
	return true, nil
}

type servicePlistValue struct {
	XMLName  xml.Name
	Text     string              `xml:",chardata"`
	Children []servicePlistValue `xml:",any"`
}

func checkServicePlist(data []byte, label, helper string) error {
	var root servicePlistValue
	if err := xml.Unmarshal(data, &root); err != nil {
		return err
	}
	if root.XMLName.Local != "plist" || len(root.Children) != 1 || root.Children[0].XMLName.Local != "dict" {
		return errors.New("unsupported service plist")
	}
	children := root.Children[0].Children
	if len(children)%2 != 0 {
		return errors.New("invalid service dictionary")
	}
	fields := map[string]servicePlistValue{}
	for i := 0; i < len(children); i += 2 {
		key := children[i]
		if key.XMLName.Local != "key" || len(key.Children) != 0 {
			return errors.New("invalid service key")
		}
		if _, exists := fields[key.Text]; exists {
			return errors.New("duplicate service key")
		}
		fields[key.Text] = children[i+1]
	}
	name, args := fields["Label"], fields["ProgramArguments"]
	if name.XMLName.Local != "string" || name.Text != label || len(name.Children) != 0 || args.XMLName.Local != "array" || len(args.Children) == 0 {
		return errors.New("service plist identity mismatch")
	}
	for _, arg := range args.Children {
		if arg.XMLName.Local != "string" || len(arg.Children) != 0 {
			return errors.New("invalid service arguments")
		}
	}
	if args.Children[0].Text != helper {
		return errors.New("service executable mismatch")
	}
	if program, exists := fields["Program"]; exists && (program.XMLName.Local != "string" || program.Text != helper || len(program.Children) != 0) {
		return errors.New("service Program overrides executable")
	}
	return nil
}

func checkServiceFiles(plist, helper, executable, label string) error {
	if err := hostguard.RootConfig(plist); err != nil {
		return err
	}
	if err := hostguard.RootConfig(helper); err != nil {
		return err
	}
	running, err := os.Open(executable)
	if err != nil {
		return err
	}
	defer running.Close()
	configured, err := os.Open(helper)
	if err != nil {
		return err
	}
	defer configured.Close()
	a, err := running.Stat()
	if err != nil {
		return err
	}
	b, err := configured.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(a, b) {
		return errors.New("service helper is not the running executable")
	}
	file, err := os.Open(plist)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil || len(data) > 64<<10 {
		return errors.New("service plist unavailable or oversized")
	}
	return checkServicePlist(data, label, helper)
}

func verifyOwnService(ctx context.Context, r BTMRecord, helper string) error {
	if err := ownedServiceMetadata(r, helper); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := hostguard.CheckProtectedPathNoACL(ctx, r.Fields["URL"], false); err != nil {
		return err
	}
	if err := hostguard.CheckProtectedPathNoACL(ctx, helper, false); err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	if err := checkServiceFiles(r.Fields["URL"], helper, executable, ownedLabel(r.Fields["Identifier"])); err != nil {
		return err
	}
	return ctx.Err()
}

func withoutOwnServices(ctx context.Context, census BTMCensus, helper string, verify func(context.Context, BTMRecord, string) error) (BTMCensus, error) {
	var kept []BTMRecord
	changed := false
	verified := map[string]bool{}
	for i, r := range census.Records {
		own, err := ownContainer(r, census.OwnServices)
		if err != nil {
			return census, err
		}
		if !own {
			if changed {
				kept = append(kept, r)
			}
			continue
		}
		if !changed {
			kept = make([]BTMRecord, 0, len(census.Records)-1)
			kept = append(kept, census.Records[:i]...)
			changed = true
		}
		for _, id := range r.Embedded {
			if verified[id] {
				continue
			}
			for _, service := range census.OwnServices {
				if service.Fields["Identifier"] == id {
					if err := verify(ctx, service, helper); err != nil {
						return census, err
					}
					verified[id] = true
				}
			}
		}
	}
	if changed {
		census.Records = kept
	}
	census.OwnServices = nil
	return census, nil
}
