// Package evidence normalizes test reports and seals bounded artifact files.
package evidence

import "time"

type TestCase struct {
	ID              string   `json:"id"`
	Suite           string   `json:"suite"`
	Name            string   `json:"name"`
	Outcome         string   `json:"outcome"`
	DurationSeconds float64  `json:"duration_seconds"`
	Failures        []string `json:"failures,omitempty"`
	Attempt         int      `json:"attempt"`
	// Container marks a failed container diagnostic, not an executed test.
	Container bool `json:"container,omitempty"`
}

type Summary struct {
	SchemaVersion    int        `json:"schema_version"`
	ParserVersion    string     `json:"parser_version"`
	ParseStatus      string     `json:"parse_status"`
	Tests            int        `json:"tests"`
	Passed           int        `json:"passed"`
	Failed           int        `json:"failed"`
	Skipped          int        `json:"skipped"`
	ExpectedFailures int        `json:"expected_failures"`
	DurationSeconds  float64    `json:"duration_seconds"`
	Cases            []TestCase `json:"cases"`
	RequiredTests    []string   `json:"required_tests"`
	XCResultSHA256   string     `json:"xcresult_sha256,omitempty"`
}

type Artifact struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	MediaType string    `json:"media_type"`
	SizeBytes int64     `json:"size_bytes"`
	SHA256    string    `json:"sha256"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Limits struct {
	MaxTotalBytes int64
	MaxFileBytes  int64
	MaxEntries    int
}
