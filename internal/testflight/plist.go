package testflight

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
)

const maxInfoPlistBytes = 1 << 20

// appInfo is the root app's identity from its Info.plist.
type appInfo struct{ id, shortVersion, version string }

// readIPAInfo reads Payload/<app>/Info.plist from the ipa, requiring every
// entry to be below Payload/<app>/ (the signer packages one app).
func readIPAInfo(r io.ReaderAt, size int64, app string) (appInfo, error) {
	archive, err := zip.NewReader(r, size)
	if err != nil {
		return appInfo{}, fmt.Errorf("ipa is not a zip archive: %w", err)
	}
	root := "Payload/" + app + "/"
	var plist *zip.File
	for _, f := range archive.File {
		if f.Name != "Payload/" && !strings.HasPrefix(f.Name, root) {
			return appInfo{}, fmt.Errorf("ipa entry %q is outside %s", clean(f.Name), root)
		}
		if f.Name == root+"Info.plist" {
			if plist != nil {
				return appInfo{}, errors.New("ipa has a duplicate Info.plist")
			}
			plist = f
		}
	}
	if plist == nil || plist.UncompressedSize64 > maxInfoPlistBytes {
		return appInfo{}, fmt.Errorf("ipa has no bounded %sInfo.plist", root)
	}
	rc, err := plist.Open()
	if err != nil {
		return appInfo{}, err
	}
	raw, err := io.ReadAll(io.LimitReader(rc, maxInfoPlistBytes+1))
	err = errors.Join(err, rc.Close())
	if err != nil {
		return appInfo{}, fmt.Errorf("ipa Info.plist: %w", err)
	}
	keys := []string{"CFBundleIdentifier", "CFBundleShortVersionString", "CFBundleVersion"}
	values, err := plistStrings(raw, keys)
	if err != nil {
		return appInfo{}, fmt.Errorf("ipa Info.plist: %w", err)
	}
	for _, key := range keys {
		if values[key] == "" {
			return appInfo{}, fmt.Errorf("ipa Info.plist lacks string %s", key)
		}
	}
	return appInfo{id: values["CFBundleIdentifier"], shortVersion: values["CFBundleShortVersionString"], version: values["CFBundleVersion"]}, nil
}

// plistStrings returns the string values of keys in a property list whose
// root is a dictionary, binary (bplist00) or XML. Values of other types are
// left out; nothing else is decoded.
func plistStrings(raw []byte, keys []string) (map[string]string, error) {
	if bytes.HasPrefix(raw, []byte("bplist00")) {
		return bplistStrings(raw, keys)
	}
	return xmlPlistStrings(raw, keys)
}

var errBplist = errors.New("malformed binary property list")

// bplistStrings reads the root dictionary of a bplist00 document: the
// 32-byte trailer, the offset table, then for each entry the key and value
// objects (ASCII or UTF-16 strings).
func bplistStrings(raw []byte, keys []string) (map[string]string, error) {
	if len(raw) < 8+32 {
		return nil, errBplist
	}
	trailer := raw[len(raw)-32:]
	offsetSize, refSize := int(trailer[6]), int(trailer[7])
	count, top, table := binary.BigEndian.Uint64(trailer[8:]), binary.BigEndian.Uint64(trailer[16:]), binary.BigEndian.Uint64(trailer[24:])
	limit := uint64(len(raw) - 32)
	if offsetSize < 1 || offsetSize > 8 || refSize < 1 || refSize > 8 || count == 0 || top >= count || table < 8 || table > limit || count > (limit-table)/uint64(offsetSize) {
		return nil, errBplist
	}
	be := func(b []byte) uint64 {
		var v uint64
		for _, c := range b {
			v = v<<8 | uint64(c)
		}
		return v
	}
	// object returns the start of object ref, inside the object area.
	object := func(ref uint64) (uint64, error) {
		if ref >= count {
			return 0, errBplist
		}
		at := table + ref*uint64(offsetSize)
		offset := be(raw[at : at+uint64(offsetSize)])
		if offset < 8 || offset >= table {
			return 0, errBplist
		}
		return offset, nil
	}
	// length decodes a marker's count: the low nibble, or a following
	// integer object when it is 0xF. It returns the count and the start of
	// the object's content.
	length := func(at uint64) (uint64, uint64, error) {
		n := uint64(raw[at] & 0x0f)
		at++
		if n != 0x0f {
			return n, at, nil
		}
		if at >= table || raw[at]&0xf0 != 0x10 {
			return 0, 0, errBplist
		}
		width := uint64(1) << (raw[at] & 0x0f)
		at++
		if width > 8 || at+width > table {
			return 0, 0, errBplist
		}
		return be(raw[at : at+width]), at + width, nil
	}
	str := func(ref uint64) (string, bool, error) {
		at, err := object(ref)
		if err != nil {
			return "", false, err
		}
		kind := raw[at] >> 4
		if kind != 0x5 && kind != 0x6 {
			return "", false, nil
		}
		n, start, err := length(at)
		if err != nil {
			return "", false, err
		}
		if kind == 0x5 {
			if n > table-start {
				return "", false, errBplist
			}
			return string(raw[start : start+n]), true, nil
		}
		if n > (table-start)/2 {
			return "", false, errBplist
		}
		units := make([]uint16, n)
		for i := range units {
			units[i] = binary.BigEndian.Uint16(raw[start+uint64(i)*2:])
		}
		return string(utf16.Decode(units)), true, nil
	}
	at, err := object(top)
	if err != nil {
		return nil, err
	}
	if raw[at]>>4 != 0xd {
		return nil, errors.New("root is not a dictionary")
	}
	n, start, err := length(at)
	if err != nil || n > (table-start)/uint64(2*refSize) {
		return nil, errBplist
	}
	want := map[string]bool{}
	for _, k := range keys {
		want[k] = true
	}
	values := map[string]string{}
	for i := range n {
		keyRef := be(raw[start+i*uint64(refSize) : start+(i+1)*uint64(refSize)])
		valueRef := be(raw[start+(n+i)*uint64(refSize) : start+(n+i+1)*uint64(refSize)])
		key, ok, err := str(keyRef)
		if err != nil {
			return nil, err
		}
		if !ok || !want[key] {
			continue
		}
		if _, dup := values[key]; dup {
			return nil, fmt.Errorf("duplicate key %s", key)
		}
		value, ok, err := str(valueRef)
		if err != nil {
			return nil, err
		}
		if ok {
			values[key] = value
		}
	}
	return values, nil
}

// xmlPlistStrings reads the root <dict> of an XML property list, skipping
// every value that is not a <string>.
func xmlPlistStrings(raw []byte, keys []string) (map[string]string, error) {
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	decoder.Strict = true
	next := func() (xml.StartElement, bool, error) {
		for {
			token, err := decoder.Token()
			if err != nil {
				return xml.StartElement{}, false, err
			}
			switch t := token.(type) {
			case xml.StartElement:
				return t, true, nil
			case xml.EndElement:
				return xml.StartElement{}, false, nil
			}
		}
	}
	element, ok, err := next()
	if err != nil || !ok || element.Name.Local != "plist" {
		return nil, errors.New("not an XML property list")
	}
	element, ok, err = next()
	if err != nil || !ok || element.Name.Local != "dict" {
		return nil, errors.New("root is not a dictionary")
	}
	want := map[string]bool{}
	for _, k := range keys {
		want[k] = true
	}
	values := map[string]string{}
	for {
		element, ok, err := next()
		if err != nil {
			return nil, errors.New("malformed XML property list")
		}
		if !ok {
			return values, nil
		}
		if element.Name.Local != "key" {
			return nil, errors.New("malformed XML property list")
		}
		var key string
		if err := decoder.DecodeElement(&key, &element); err != nil {
			return nil, errors.New("malformed XML property list")
		}
		value, ok, err := next()
		if err != nil || !ok {
			return nil, errors.New("malformed XML property list")
		}
		if value.Name.Local != "string" || !want[key] {
			if err := decoder.Skip(); err != nil {
				return nil, errors.New("malformed XML property list")
			}
			continue
		}
		if _, dup := values[key]; dup {
			return nil, fmt.Errorf("duplicate key %s", key)
		}
		var s string
		if err := decoder.DecodeElement(&s, &value); err != nil {
			return nil, errors.New("malformed XML property list")
		}
		values[key] = s
	}
}
