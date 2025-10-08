package certs

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
)

// ErrEmptyRecord indicates the input string didn't contain any certificate
// data when attempting to parse.
var ErrEmptyRecord = errors.New("certs: empty record")

// Record represents the useful details extracted from a TLS certificate.
// It is intentionally lightweight so it can be marshalled as JSON and stored
// verbatim inside the certs.passive artifact.
type Record struct {
	Source            string   `json:"source,omitempty"`
	CommonName        string   `json:"common_name,omitempty"`
	DNSNames          []string `json:"dns_names,omitempty"`
	Subject           string   `json:"subject,omitempty"`
	Issuer            string   `json:"issuer,omitempty"`
	NotBefore         string   `json:"not_before,omitempty"`
	NotAfter          string   `json:"not_after,omitempty"`
	SerialNumber      string   `json:"serial_number,omitempty"`
	FingerprintSHA256 string   `json:"fingerprint_sha256,omitempty"`
	FingerprintSHA1   string   `json:"fingerprint_sha1,omitempty"`
	FingerprintMD5    string   `json:"fingerprint_md5,omitempty"`
}

// Normalize removes empty entries, lower-cases domain data and sorts the DNS
// names slice so records produced by different sources share a stable
// representation.
func (r *Record) Normalize() {
	r.CommonName = strings.TrimSpace(strings.ToLower(r.CommonName))

	unique := make(map[string]struct{})
	var cleaned []string
	for _, name := range r.DNSNames {
		trimmed := strings.TrimSpace(strings.ToLower(name))
		if trimmed == "" {
			continue
		}
		if _, ok := unique[trimmed]; ok {
			continue
		}
		unique[trimmed] = struct{}{}
		cleaned = append(cleaned, trimmed)
	}
	sort.Strings(cleaned)
	r.DNSNames = cleaned

	r.Subject = strings.TrimSpace(r.Subject)
	r.Issuer = strings.TrimSpace(r.Issuer)
	r.NotBefore = strings.TrimSpace(r.NotBefore)
	r.NotAfter = strings.TrimSpace(r.NotAfter)
	r.SerialNumber = strings.TrimSpace(r.SerialNumber)
	r.FingerprintSHA256 = strings.TrimSpace(strings.ToLower(r.FingerprintSHA256))
	r.FingerprintSHA1 = strings.TrimSpace(strings.ToLower(r.FingerprintSHA1))
	r.FingerprintMD5 = strings.TrimSpace(strings.ToLower(r.FingerprintMD5))
	r.Source = strings.TrimSpace(r.Source)
}

// Marshal encodes the record to JSON after normalizing the data to ensure a
// deterministic output representation.
func (r Record) Marshal() (string, error) {
	r.Normalize()
	encoded, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// Parse converts a JSON representation back into a record. The returned record
// is normalized to simplify downstream processing.
func Parse(raw string) (Record, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Record{}, ErrEmptyRecord
	}
	var r Record
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return Record{}, err
	}
	r.Normalize()
	return r, nil
}

// Key builds a stable identifier for deduplication. Whenever the certificate
// exposes a fingerprint that value is prioritised; otherwise the combination of
// issuer + serial number or the DNS names are used as a fallback.
func (r Record) Key() string {
	if r.FingerprintSHA256 != "" {
		return "sha256:" + r.FingerprintSHA256
	}
	if r.FingerprintSHA1 != "" {
		return "sha1:" + r.FingerprintSHA1
	}
	if r.SerialNumber != "" && r.Issuer != "" {
		return strings.ToLower(r.SerialNumber + "|" + r.Issuer)
	}
	if r.CommonName != "" {
		return "cn:" + r.CommonName
	}
	if len(r.DNSNames) > 0 {
		return "dns:" + strings.Join(r.DNSNames, ",")
	}
	return ""
}

// AllNames returns the collection of names associated with the certificate
// (common name + SANs) without duplicates.
func (r Record) AllNames() []string {
	seen := make(map[string]struct{})
	var names []string
	add := func(value string) {
		value = strings.TrimSpace(strings.ToLower(value))
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		names = append(names, value)
	}
	add(r.CommonName)
	for _, n := range r.DNSNames {
		add(n)
	}
	sort.Strings(names)
	return names
}
