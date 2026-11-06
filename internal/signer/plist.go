package signer

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Property list values decode to: map[string]any (dict), []any (array),
// string, int64 (integer), float64 (real), bool, time.Time (date) and []byte
// (data). Profiles and codesign's entitlement output are XML plists; binary
// plists never reach this decoder (security cms and codesign print XML).

const maxPlistDepth = 64

var errPlist = errors.New("malformed XML property list")

// decodePlist parses one XML property list document.
func decodePlist(raw []byte) (any, error) {
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	decoder.Strict = true
	for {
		token, err := decoder.Token()
		if err != nil {
			return nil, errPlist
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		if start.Name.Local != "plist" {
			return nil, errPlist
		}
		value, err := plistElement(decoder, nil, 0)
		if err != nil {
			return nil, err
		}
		if value == nil {
			return nil, errPlist
		}
		// </plist> and nothing but whitespace, comments or processing
		// instructions after it.
		if err := plistEnd(decoder); err != nil {
			return nil, err
		}
		for {
			token, err := decoder.Token()
			if err == io.EOF {
				return value, nil
			}
			if err != nil {
				return nil, errPlist
			}
			switch t := token.(type) {
			case xml.CharData:
				if len(bytes.TrimSpace(t)) != 0 {
					return nil, errPlist
				}
			case xml.Comment, xml.ProcInst:
			default:
				return nil, errPlist
			}
		}
	}
}

// plistEnd consumes whitespace up to the enclosing end element.
func plistEnd(decoder *xml.Decoder) error {
	for {
		token, err := decoder.Token()
		if err != nil {
			return errPlist
		}
		switch t := token.(type) {
		case xml.EndElement:
			return nil
		case xml.CharData:
			if len(bytes.TrimSpace(t)) != 0 {
				return errPlist
			}
		case xml.Comment:
		default:
			return errPlist
		}
	}
}

// plistElement reads the next value element. With start nil it first skips
// whitespace; it returns nil, nil at the enclosing end element.
func plistElement(decoder *xml.Decoder, start *xml.StartElement, depth int) (any, error) {
	if depth > maxPlistDepth {
		return nil, errPlist
	}
	for start == nil {
		token, err := decoder.Token()
		if err != nil {
			return nil, errPlist
		}
		switch t := token.(type) {
		case xml.StartElement:
			start = &t
		case xml.EndElement:
			return nil, nil
		case xml.CharData:
			if len(bytes.TrimSpace(t)) != 0 {
				return nil, errPlist
			}
		case xml.Comment:
		default:
			return nil, errPlist
		}
	}
	switch start.Name.Local {
	case "dict":
		dict := map[string]any{}
		for {
			key, err := plistElement(decoder, nil, depth+1)
			if err != nil {
				return nil, err
			}
			if key == nil {
				return dict, nil
			}
			name, ok := key.(plistKey)
			if !ok {
				return nil, errPlist
			}
			if _, duplicate := dict[string(name)]; duplicate {
				return nil, errPlist
			}
			value, err := plistElement(decoder, nil, depth+1)
			if err != nil || value == nil {
				return nil, errPlist
			}
			if _, isKey := value.(plistKey); isKey {
				return nil, errPlist
			}
			dict[string(name)] = value
		}
	case "array":
		array := []any{}
		for {
			value, err := plistElement(decoder, nil, depth+1)
			if err != nil {
				return nil, err
			}
			if value == nil {
				return array, nil
			}
			if _, isKey := value.(plistKey); isKey {
				return nil, errPlist
			}
			array = append(array, value)
		}
	case "true", "false":
		if err := plistEnd(decoder); err != nil {
			return nil, err
		}
		return start.Name.Local == "true", nil
	}
	var text string
	if err := decoder.DecodeElement(&text, start); err != nil {
		return nil, errPlist
	}
	switch start.Name.Local {
	case "key":
		return plistKey(text), nil
	case "string":
		return text, nil
	case "integer":
		value, err := strconv.ParseInt(strings.TrimSpace(text), 10, 64)
		if err != nil {
			return nil, errPlist
		}
		return value, nil
	case "real":
		value, err := strconv.ParseFloat(strings.TrimSpace(text), 64)
		if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
			return nil, errPlist
		}
		return value, nil
	case "date":
		value, err := time.Parse(time.RFC3339, strings.TrimSpace(text))
		if err != nil {
			return nil, errPlist
		}
		return value.UTC(), nil
	case "data":
		value, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(text), ""))
		if err != nil {
			return nil, errPlist
		}
		return value, nil
	}
	return nil, errPlist
}

type plistKey string

// jsonToPlist converts a JSON value decoded with UseNumber to the property
// list domain: integers become int64, other numbers float64.
func jsonToPlist(value any) (any, error) {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			converted, err := jsonToPlist(item)
			if err != nil {
				return nil, err
			}
			out[key] = converted
		}
		return out, nil
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			converted, err := jsonToPlist(item)
			if err != nil {
				return nil, err
			}
			out[i] = converted
		}
		return out, nil
	case json.Number:
		if integer, err := v.Int64(); err == nil {
			return integer, nil
		}
		real, err := v.Float64()
		if err != nil || math.IsNaN(real) || math.IsInf(real, 0) {
			return nil, fmt.Errorf("number %s is not representable", v)
		}
		return real, nil
	case string, bool:
		return v, nil
	case nil:
		return nil, errors.New("null has no property list form")
	}
	return nil, fmt.Errorf("unsupported value %T", value)
}

// encodePlist writes value as a deterministic XML property list: dict keys
// sorted, no dates or data (entitlements carry neither).
func encodePlist(value any) ([]byte, error) {
	var buffer bytes.Buffer
	buffer.WriteString(xml.Header)
	buffer.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	buffer.WriteString(`<plist version="1.0">` + "\n")
	if err := encodePlistValue(&buffer, value, 0); err != nil {
		return nil, err
	}
	buffer.WriteString("\n</plist>\n")
	return buffer.Bytes(), nil
}

func encodePlistValue(buffer *bytes.Buffer, value any, depth int) error {
	if depth > maxPlistDepth {
		return errPlist
	}
	escape := func(s string) error {
		return xml.EscapeText(buffer, []byte(s))
	}
	switch v := value.(type) {
	case map[string]any:
		buffer.WriteString("<dict>")
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			buffer.WriteString("<key>")
			if err := escape(key); err != nil {
				return err
			}
			buffer.WriteString("</key>")
			if err := encodePlistValue(buffer, v[key], depth+1); err != nil {
				return err
			}
		}
		buffer.WriteString("</dict>")
	case []any:
		buffer.WriteString("<array>")
		for _, item := range v {
			if err := encodePlistValue(buffer, item, depth+1); err != nil {
				return err
			}
		}
		buffer.WriteString("</array>")
	case string:
		buffer.WriteString("<string>")
		if err := escape(v); err != nil {
			return err
		}
		buffer.WriteString("</string>")
	case bool:
		if v {
			buffer.WriteString("<true/>")
		} else {
			buffer.WriteString("<false/>")
		}
	case int64:
		buffer.WriteString("<integer>" + strconv.FormatInt(v, 10) + "</integer>")
	case float64:
		buffer.WriteString("<real>" + strconv.FormatFloat(v, 'g', -1, 64) + "</real>")
	default:
		return fmt.Errorf("unsupported entitlement value %T", value)
	}
	return nil
}
