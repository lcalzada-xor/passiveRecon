package sources

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"passive-rec/internal/certs"
)

func TestCensysPagination(t *testing.T) {
	var serverURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "id" || password != "secret" {
			t.Fatalf("unexpected auth: %v %s/%s", ok, username, password)
		}

		switch r.URL.Query().Get("page") {
		case "", "1":
			if got := r.URL.Query().Get("q"); got != "parsed.names: example.com" {
				t.Fatalf("unexpected query: %s", got)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
  "result": {
    "hits": [
      {
        "name": "example.com",
        "parsed": {
          "subject": {"common_name": "example.com"},
          "names": ["example.com", "www.example.com"]
        }
      }
    ],
    "links": {"next": "` + serverURL + `/api/v2/certificates/search?page=2"}
  }
}`))
		case "2":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
  "result": {
    "hits": [
      {
        "name": "alt.example.com",
        "parsed": {
          "subject": {"common_name": "alt.example.com"},
          "names": ["alt.example.com", "legacy.example.com"]
        }
      }
    ],
    "links": {"next": ""}
  }
}`))
		default:
			t.Fatalf("unexpected page: %s", r.URL.Query().Get("page"))
		}
	}))
	defer srv.Close()

	serverURL = srv.URL
	oldURL := censysBaseURL
	oldClient := censysHTTPClient
	censysBaseURL = serverURL + "/api/v2/certificates/search"
	censysHTTPClient = srv.Client()
	defer func() {
		censysBaseURL = oldURL
		censysHTTPClient = oldClient
	}()

	out := make(chan string, 16)
	if err := Censys(context.Background(), "example.com", "id", "secret", out); err != nil {
		t.Fatalf("censys returned error: %v", err)
	}

	var names []string
	for len(out) > 0 {
		raw := <-out
		record, err := certs.Parse(strings.TrimSpace(strings.TrimPrefix(raw, "cert:")))
		if err != nil {
			t.Fatalf("parse record: %v", err)
		}
		if record.Source != "censys" {
			t.Fatalf("unexpected source %q", record.Source)
		}
		names = append(names, record.AllNames()...)
	}

	want := []string{"alt.example.com", "example.com", "legacy.example.com", "www.example.com"}
	sort.Strings(names)
	sort.Strings(want)
	if len(names) != len(want) {
		t.Fatalf("unexpected name count %d want %d", len(names), len(want))
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("unexpected names set: got %#v want %#v", names, want)
		}
	}
}

func TestCensysMissingCredentials(t *testing.T) {
	out := make(chan string, 1)
	if err := Censys(context.Background(), "example.com", "", "", out); err == nil {
		t.Fatal("expected error for missing credentials")
	}
	select {
	case got := <-out:
		want := "meta: censys missing API credentials"
		if got != want {
			t.Fatalf("unexpected meta message: got %q want %q", got, want)
		}
	default:
		t.Fatal("expected meta message when credentials missing")
	}
}

func TestCensysHTTPErrorIncludesMeta(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	oldURL := censysBaseURL
	oldClient := censysHTTPClient
	censysBaseURL = srv.URL
	censysHTTPClient = srv.Client()
	defer func() {
		censysBaseURL = oldURL
		censysHTTPClient = oldClient
	}()

	out := make(chan string, 1)
	err := Censys(context.Background(), "example.com", "id", "secret", out)
	if err == nil {
		t.Fatal("expected error for non-200 response")
	}
	if !strings.Contains(err.Error(), "unexpected status") {
		t.Fatalf("unexpected error value: %v", err)
	}

	select {
	case got := <-out:
		want := "meta: censys unexpected HTTP status 429"
		if got != want {
			t.Fatalf("unexpected meta message: got %q want %q", got, want)
		}
	default:
		t.Fatal("expected meta message for HTTP error")
	}
}

func TestCensysDeduplicatesCaseInsensitive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
  "result": {
    "hits": [
      {
        "name": "Example.com",
        "parsed": {
          "subject": {"common_name": "EXAMPLE.com"},
          "names": ["example.com", "WWW.EXAMPLE.COM"]
        }
      }
    ],
    "links": {"next": ""}
  }
}`))
	}))
	defer srv.Close()

	oldURL := censysBaseURL
	oldClient := censysHTTPClient
	censysBaseURL = srv.URL
	censysHTTPClient = srv.Client()
	defer func() {
		censysBaseURL = oldURL
		censysHTTPClient = oldClient
	}()

	out := make(chan string, 4)
	if err := Censys(context.Background(), "example.com", "id", "secret", out); err != nil {
		t.Fatalf("censys returned error: %v", err)
	}

	var records []certs.Record
	for len(out) > 0 {
		raw := <-out
		record, err := certs.Parse(strings.TrimSpace(strings.TrimPrefix(raw, "cert:")))
		if err != nil {
			t.Fatalf("parse record: %v", err)
		}
		records = append(records, record)
	}

	if len(records) != 1 {
		t.Fatalf("expected a single record, got %d", len(records))
	}

	names := records[0].AllNames()
	sort.Strings(names)
	want := []string{"example.com", "www.example.com"}
	if len(names) != len(want) {
		t.Fatalf("unexpected names count %d want %d", len(names), len(want))
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("unexpected names: got %#v want %#v", names, want)
		}
	}
}

func TestCensysRelativeNextLink(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Query().Get("page") {
		case "", "1":
			w.Write([]byte(`{
  "result": {
    "hits": [
      {"name": "page1.example.com"}
    ],
    "links": {"next": "/api/v2/certificates/search?page=2"}
  }
}`))
		case "2":
			w.Write([]byte(`{
  "result": {
    "hits": [
      {"name": "page2.example.com"}
    ],
    "links": {"next": ""}
  }
}`))
		default:
			t.Fatalf("unexpected page requested: %s", r.URL.Query().Get("page"))
		}
	}))
	defer srv.Close()

	oldURL := censysBaseURL
	oldClient := censysHTTPClient
	censysBaseURL = srv.URL + "/api/v2/certificates/search"
	censysHTTPClient = srv.Client()
	defer func() {
		censysBaseURL = oldURL
		censysHTTPClient = oldClient
	}()

	out := make(chan string, 4)
	if err := Censys(context.Background(), "example.com", "id", "secret", out); err != nil {
		t.Fatalf("censys returned error: %v", err)
	}

	var records []certs.Record
	for len(out) > 0 {
		raw := <-out
		record, err := certs.Parse(strings.TrimSpace(strings.TrimPrefix(raw, "cert:")))
		if err != nil {
			t.Fatalf("parse record: %v", err)
		}
		records = append(records, record)
	}

	sort.Slice(records, func(i, j int) bool {
		return records[i].CommonName < records[j].CommonName
	})
	want := []string{"page1.example.com", "page2.example.com"}
	if len(records) != len(want) {
		t.Fatalf("unexpected result length %d (want %d)", len(records), len(want))
	}
	for i, v := range want {
		names := records[i].AllNames()
		if len(names) != 1 || names[0] != v {
			t.Fatalf("unexpected record %d: names=%#v want %s", i, names, v)
		}
	}
}
