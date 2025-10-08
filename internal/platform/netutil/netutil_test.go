package netutil

import "testing"

func TestNormalizeDomain(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		" example.com ":              "example.com",
		"# comment":                  "",
		"":                           "",
		"   ":                        "",
		"example.com extra metadata": "example.com",
		"user@example.com":           "example.com",
		"http://user:pass@WWW.Example.com:8443/path?query#frag": "www.example.com",
		"sub.EXAMPLE.com/login":                                 "sub.example.com",
		"[2001:db8::1]":                                         "2001:db8::1",
		"https://[2001:db8::1]:8443/path":                       "2001:db8::1",
		"[2001:db8::1]:8443":                                    "2001:db8::1",
		"*.example.com":                                         "",
		"test.*.example.com":                                    "",
		"WWW.Wildcard.*":                                        "",
		"https://www.EXAMPLE.com":                               "www.example.com",
		"http://example.com/path/to/page":                       "example.com",
		"https://example.com?query=1":                           "example.com",
		"http://[2001:db8::1]/path":                             "2001:db8::1",
		"No results found":                                      "",
		"NO":                                                    "",
	}

	for input, want := range tests {
		input, want := input, want
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			if got := NormalizeDomain(input); got != want {
				t.Fatalf("NormalizeDomain(%q) = %q, want %q", input, got, want)
			}
		})
	}
}
