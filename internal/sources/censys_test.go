package sources

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
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

	results := make(map[string]bool)
	for len(out) > 0 {
		results[<-out] = true
	}

	expected := []string{"example.com", "www.example.com", "alt.example.com", "legacy.example.com"}
	for _, name := range expected {
		if !results[name] {
			t.Fatalf("missing result %s", name)
		}
	}
	if len(results) != len(expected) {
		t.Fatalf("unexpected number of results: %d", len(results))
	}
}

func TestCensysMissingCredentials(t *testing.T) {
	out := make(chan string, 1)
	if err := Censys(context.Background(), "example.com", "", "", out); err == nil {
		t.Fatal("expected error for missing credentials")
	}
	if len(out) != 0 {
		t.Fatalf("unexpected output when credentials missing: %d", len(out))
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

	var results []string
	for len(out) > 0 {
		results = append(results, <-out)
	}

	if len(results) != 2 {
		t.Fatalf("expected two unique results, got %d: %#v", len(results), results)
	}

	seen := map[string]bool{}
	for _, r := range results {
		seen[r] = true
	}
	if !seen["example.com"] || !seen["www.example.com"] {
		t.Fatalf("expected example.com and www.example.com, got %#v", results)
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

	var results []string
	for len(out) > 0 {
		results = append(results, <-out)
	}

	sort.Strings(results)
	want := []string{"page1.example.com", "page2.example.com"}
	if len(results) != len(want) {
		t.Fatalf("unexpected result length %d (want %d)", len(results), len(want))
	}
	for i, v := range want {
		if results[i] != v {
			t.Fatalf("unexpected result set: got %#v want %#v", results, want)
		}
	}
}
