package worker

import (
	"errors"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// BTMRecord preserves registration metadata, not an executable trust claim.
// UUID, generation, flags and disposition changes all require renewed review.
type BTMRecord struct {
	Fields   map[string]string `json:"fields"`
	Embedded []string          `json:"embedded,omitempty"`
}

type BTMCensus struct {
	Identifier string            `json:"identifier"`
	Metadata   map[string]string `json:"metadata"`
	Records    []BTMRecord       `json:"records"`
	// Ephemeral attribution from UID -2; never stored as reviewed authority.
	OwnServices []BTMRecord `json:"-"`
}

var btmHeader = regexp.MustCompile(`^Records for UID (-?[0-9]+) : ([[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12})$`)
var btmRecordHeader = regexp.MustCompile(`^#([1-9][0-9]*):$`)
var btmReference = regexp.MustCompile(`^#([1-9][0-9]*): (.+)$`)
var btmUUID = regexp.MustCompile(`^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$`)

// Zone offsets are limited to real-world ranges (hours 00-14, minutes 00-59):
// time.Parse alone accepts +24:00 and +00:60.
var btmLastUse = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}(Z|[+-](0[0-9]|1[0-4]):[0-5][0-9])$`)

// btmLastUseField is the macOS 27 per-record "Last Use: <timestamp>" line.
const btmLastUseField = "Last Use"

// checkBTMLastUse validates the macOS 27 "Last Use" value. It is volatile
// (rewritten on every daemon or app run) and never identity: callers validate
// and discard it, so it cannot reach Fields, a manifest, a digest or review.
func checkBTMLastUse(value string, seen *bool) error {
	if *seen {
		return errors.New("duplicate background last use")
	}
	*seen = true
	if value == "(null)" {
		return nil
	}
	if !btmLastUse.MatchString(value) {
		return errors.New("invalid background last use")
	}
	if _, err := time.Parse("2006-01-02 15:04:05Z07:00", value); err != nil {
		return errors.New("invalid background last use")
	}
	return nil
}

func parseBackgroundItems(output string, uid uint32) (BTMCensus, error) {
	var census BTMCensus
	if len(output) > 1<<20 || !utf8.ValidString(output) || strings.ContainsRune(output, 0) {
		return census, errors.New("invalid or oversized background census")
	}
	found, target, items, embedded, explicitEmpty, lastUse := false, false, false, false, false, false
	var record *BTMRecord
	ids, uuids := map[string]bool{}, map[string]bool{}
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "Records for UID") {
			match := btmHeader.FindStringSubmatch(line)
			if match == nil {
				return census, errors.New("ambiguous background UID section")
			}
			target = match[1] == strconv.FormatUint(uint64(uid), 10)
			if target {
				if found {
					return census, errors.New("duplicate background UID section")
				}
				found = true
				census.Identifier = match[2]
				census.Metadata = map[string]string{}
			}
			continue
		}
		if !target || line == "" || strings.Trim(line, "=") == "" {
			continue
		}
		if match := btmRecordHeader.FindStringSubmatch(line); match != nil {
			n, err := strconv.Atoi(match[1])
			if err != nil || !items || explicitEmpty || n != len(census.Records)+1 || n > 4096 {
				return census, errors.New("invalid background record sequence")
			}
			census.Records = append(census.Records, BTMRecord{Fields: map[string]string{}})
			record = &census.Records[len(census.Records)-1]
			embedded, lastUse = false, false
			continue
		}
		if record == nil {
			if line == "Items:" || line == "Items: 0" {
				if items {
					return census, errors.New("duplicate background items section")
				}
				items = true
				explicitEmpty = line == "Items: 0"
				continue
			}
			key, value, ok := strings.Cut(line, ": ")
			if !ok || items || (key != "ServiceManagement migrated" && key != "LaunchServices registered") || (value != "true" && value != "false") || census.Metadata[key] != "" {
				return census, errors.New("unsupported background section metadata")
			}
			census.Metadata[key] = value
			continue
		}
		// Last Use may follow the embedded list; "#N: " references never begin with it.
		if value, ok := strings.CutPrefix(line, btmLastUseField+": "); ok {
			if err := checkBTMLastUse(value, &lastUse); err != nil {
				return census, err
			}
			continue
		}
		if line == "Embedded Item Identifiers:" {
			if embedded {
				return census, errors.New("duplicate embedded background references")
			}
			embedded = true
			continue
		}
		if embedded {
			match := btmReference.FindStringSubmatch(line)
			if match == nil {
				return census, errors.New("invalid embedded background reference")
			}
			n, err := strconv.Atoi(match[1])
			if err != nil || n != len(record.Embedded)+1 {
				return census, errors.New("invalid embedded reference sequence")
			}
			record.Embedded = append(record.Embedded, match[2])
			continue
		}
		key, value, ok := strings.Cut(line, ": ")
		if !ok || value == "" || record.Fields[key] != "" {
			return census, errors.New("missing or duplicate background field")
		}
		switch key {
		case "UUID", "Name", "Developer Name", "Team Identifier", "Type", "Flags", "Disposition", "Identifier", "URL", "Generation", "Bundle Identifier", "Parent Identifier":
			record.Fields[key] = value
		default:
			return census, errors.New("unsupported background record field")
		}
	}
	if !found || !items || census.Metadata["ServiceManagement migrated"] == "" || census.Metadata["LaunchServices registered"] == "" {
		return census, errors.New("complete explicit job-UID background census unavailable")
	}
	for _, r := range census.Records {
		for _, key := range []string{"UUID", "Name", "Developer Name", "Type", "Flags", "Disposition", "Identifier", "URL", "Generation"} {
			if r.Fields[key] == "" {
				return census, errors.New("incomplete background record")
			}
		}
		if !btmUUID.MatchString(r.Fields["UUID"]) || uuids[r.Fields["UUID"]] || ids[r.Fields["Identifier"]] {
			return census, errors.New("duplicate or invalid background identity")
		}
		if _, err := strconv.ParseUint(r.Fields["Generation"], 10, 64); err != nil {
			return census, errors.New("invalid background generation")
		}
		uuids[r.Fields["UUID"]], ids[r.Fields["Identifier"]] = true, true
	}
	// Presentation ordering alone is not a registration change.
	sort.Slice(census.Records, func(i, j int) bool {
		return census.Records[i].Fields["Identifier"] < census.Records[j].Fields["Identifier"]
	})
	for i := range census.Records {
		sort.Strings(census.Records[i].Embedded)
	}
	var err error
	census.OwnServices, err = ownedReferences(output, census)
	return census, err
}

// registrationPaths resolves only the audited schema's app and nested-code forms.
// No type is trusted by this classification: each path still needs code review,
// signature verification, protected ownership and an exact accepted manifest.
func registrationPaths(census BTMCensus) (map[string]string, []string) {
	paths := map[string]string{}
	byID := map[string]BTMRecord{}
	for _, r := range census.Records {
		byID[r.Fields["Identifier"]] = r
	}
	var problems []string
	if census.Metadata["ServiceManagement migrated"] != "true" || census.Metadata["LaunchServices registered"] != "true" {
		problems = append(problems, "background migration/registration census is not complete")
	}
	for _, r := range census.Records {
		f, id := r.Fields, r.Fields["Identifier"]
		refuse := func(reason string) { problems = append(problems, id+": "+reason) }
		if own, err := ownContainer(r, census.OwnServices); err != nil {
			refuse(err.Error())
			continue
		} else if own {
			// Structural attribution only. Native collection must verify files
			// before removing these from the reviewed third-party census.
			continue
		}
		if f["Flags"] != "[  ] (0)" && f["Flags"] != "[ sandboxed ] (0x40)" {
			refuse("unsupported flags")
			continue
		}
		switch f["Type"] {
		case "developer (0x20)":
			if f["URL"] != "(null)" || f["Parent Identifier"] != "" || f["Bundle Identifier"] != "" || f["Disposition"] != "[disabled, allowed, notified] (0xa)" || len(r.Embedded) == 0 {
				refuse("unsupported developer container")
			}
			seen := map[string]bool{}
			for _, ref := range r.Embedded {
				child, ok := byID[ref]
				if !ok || seen[ref] || child.Fields["Type"] == "developer (0x20)" {
					refuse("unresolved or duplicate embedded reference")
				}
				seen[ref] = true
			}
			continue
		case "app (0x2)":
			if f["Parent Identifier"] != "" || f["Disposition"] != "[disabled, allowed, notified] (0xa)" {
				refuse("application can autostart or has unsupported disposition")
				continue
			}
			path := f["URL"]
			if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Ext(path) != ".app" {
				refuse("application path unsupported")
				continue
			}
			paths[id] = path
		case "dock tile (0x80)", "spotlight (0x40)", "quicklook (0x800)":
			if f["Disposition"] != "[enabled, allowed, notified] (0xb)" && f["Disposition"] != "[enabled, allowed, not notified] (0x3)" {
				refuse("extension disposition unsupported")
				continue
			}
			parent, ok := byID[f["Parent Identifier"]]
			rel := f["URL"]
			if !ok || parent.Fields["Type"] != "app (0x2)" || !filepath.IsAbs(parent.Fields["URL"]) || !strings.HasPrefix(rel, "Contents/") || filepath.IsAbs(rel) || filepath.Clean(rel) != rel {
				refuse("extension parent or relative path unavailable")
				continue
			}
			paths[id] = filepath.Join(parent.Fields["URL"], rel)
		default:
			refuse("automatic-start or unknown registration type is not eligible")
			continue
		}
		if len(r.Embedded) != 0 || f["Bundle Identifier"] == "" || f["Team Identifier"] == "" || f["Team Identifier"] == "(null)" {
			refuse("code identity or relationship unsupported")
		}
		var prefix string
		switch f["Type"] {
		case "app (0x2)":
			prefix = "2."
		case "dock tile (0x80)":
			prefix = "128."
		case "spotlight (0x40)":
			prefix = "64."
		case "quicklook (0x800)":
			prefix = "2048."
		}
		if id != prefix+f["Bundle Identifier"] {
			refuse("registration identifier does not bind its bundle")
		}
	}
	return paths, problems
}
