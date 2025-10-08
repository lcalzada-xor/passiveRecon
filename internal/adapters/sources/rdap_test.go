package sources

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestSummarizeRDAP(t *testing.T) {
	t.Parallel()

	payload := rdapResponse{
		LDHName:     "EXAMPLE.COM",
		Status:      []string{" client delete prohibited ", "client transfer prohibited", "CLIENT DELETE PROHIBITED"},
		Nameservers: []rdapObject{{LDHName: "A.IANA-SERVERS.NET"}, {UnicodeName: "b.iana-servers.net"}, {LDHName: ""}},
		Events: []rdapEvent{
			{Action: "registration", Date: "1995-08-14T04:00:00Z"},
			{Action: "expiration", Date: "2026-08-13T04:00:00Z"},
			{Action: "last changed", Date: "2025-08-14T07:01:39Z"},
			{Action: "last update of RDAP database", Date: "2025-10-06T15:54:40Z"},
		},
		Entities: []rdapEntity{{
			Roles:     []string{"registrar"},
			Handle:    "376",
			PublicIDs: []rdapPublicID{{Type: "IANA Registrar ID", Identifier: "376"}},
			VCardArray: []any{
				"vcard",
				[]any{
					[]any{"version", map[string]any{}, "text", "4.0"},
					[]any{"fn", map[string]any{}, "text", "Example Registrar"},
				},
			},
		}},
	}

	summary := summarizeRDAP(&payload, "example.com")

	if summary.Domain != "example.com" {
		t.Fatalf("Domain = %q, want example.com", summary.Domain)
	}
	wantStatuses := []string{"client delete prohibited", "client transfer prohibited"}
	if diff := diffStrings(summary.Statuses, wantStatuses); diff != "" {
		t.Fatalf("Statuses mismatch: %s", diff)
	}
	wantNameservers := []string{"a.iana-servers.net", "b.iana-servers.net"}
	if diff := diffStrings(summary.Nameservers, wantNameservers); diff != "" {
		t.Fatalf("Nameservers mismatch: %s", diff)
	}
	if summary.Created != "1995-08-14T04:00:00Z" {
		t.Fatalf("Created = %q", summary.Created)
	}
	if summary.Expires != "2026-08-13T04:00:00Z" {
		t.Fatalf("Expires = %q", summary.Expires)
	}
	if summary.Updated != "2025-08-14T07:01:39Z" {
		t.Fatalf("Updated = %q", summary.Updated)
	}
	if summary.RDAPLastUpdated != "2025-10-06T15:54:40Z" {
		t.Fatalf("RDAPLastUpdated = %q", summary.RDAPLastUpdated)
	}
	if summary.Registrar != "Example Registrar" {
		t.Fatalf("Registrar = %q", summary.Registrar)
	}
	if summary.RegistrarID != "376" {
		t.Fatalf("RegistrarID = %q", summary.RegistrarID)
	}
}

func TestRDAPFetch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/example.com") {
			http.NotFound(w, r)
			return
		}
		resp := rdapResponse{
			LDHName: "EXAMPLE.COM",
			Status:  []string{"active"},
			Nameservers: []rdapObject{
				{LDHName: "ns1.example.com"},
				{UnicodeName: "ns2.example.com"},
			},
			Events: []rdapEvent{
				{Action: "registration", Date: "2020-01-01T00:00:00Z"},
				{Action: "expiration", Date: "2025-01-01T00:00:00Z"},
			},
			Entities: []rdapEntity{{
				Roles:     []string{"registrar"},
				PublicIDs: []rdapPublicID{{Type: "IANA Registrar ID", Identifier: "999"}},
				VCardArray: []any{
					"vcard",
					[]any{
						[]any{"fn", map[string]any{}, "text", "Test Registrar"},
					},
				},
			}},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	oldBase := rdapBaseURL
	oldClient := rdapHTTPClient
	rdapBaseURL = server.URL + "/"
	rdapHTTPClient = server.Client()
	defer func() {
		rdapBaseURL = oldBase
		rdapHTTPClient = oldClient
	}()

	out := make(chan string, 32)
	if err := RDAP(context.Background(), "example.com", out); err != nil {
		t.Fatalf("RDAP: %v", err)
	}

	close(out)
	var lines []string
	for line := range out {
		lines = append(lines, line)
	}

	want := []string{
		"meta: rdap domain: example.com",
		"meta: rdap registrar: Test Registrar (IANA 999)",
		"meta: rdap status: active",
		"meta: rdap nameserver: ns1.example.com",
		"meta: rdap nameserver: ns2.example.com",
		"meta: rdap created: 2020-01-01T00:00:00Z",
		"meta: rdap expiration: 2025-01-01T00:00:00Z",
		"rdap: domain=example.com",
		"rdap: registrar=Test Registrar (IANA 999)",
		"rdap: status=active",
		"rdap: nameserver=ns1.example.com",
		"rdap: nameserver=ns2.example.com",
		"rdap: event=registration 2020-01-01T00:00:00Z",
		"rdap: event=expiration 2025-01-01T00:00:00Z",
	}

	if diff := diffStrings(lines, want); diff != "" {
		t.Fatalf("unexpected lines: %s", diff)
	}
}

func TestNormalizeRDAPDomain(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"example.com":               "example.com",
		"*.example.com":             "example.com",
		"*example.com":              "example.com",
		"https://*.example.com":     "example.com",
		"https://*example.com":      "example.com",
		"":                          "",
		"invalid":                   "",
		"*.sub.*.example.com":       "sub.example.com",
		"https://*.sub.example.com": "sub.example.com",
	}

	for input, want := range cases {
		got := normalizeRDAPDomain(input)
		if got != want {
			t.Fatalf("normalizeRDAPDomain(%q) = %q, want %q", input, got, want)
		}
	}
}

func diffStrings(got, want []string) string {
	if len(got) != len(want) {
		return "length mismatch"
	}
	for i := range got {
		if got[i] != want[i] {
			return "mismatch at index " + strconv.Itoa(i) + ": got " + got[i] + " want " + want[i]
		}
	}
	return ""
}
