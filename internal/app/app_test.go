package app

import "testing"

func TestSmallURL(t *testing.T) {
	for _, c := range []struct {
		scheme, listen string
		def            int
		want           string
	}{
		{"gopher", ":70", 70, "gopher://lawn.example/"},
		{"gemini", ":1965", 1965, "gemini://lawn.example/"},
		{"gopher", "127.0.0.1:7070", 70, "gopher://lawn.example:7070/"},
		{"gemini", "127.0.0.1:0", 1965, "gemini://lawn.example/"},
		{"gopher", "", 70, ""},
	} {
		if got := smallURL(c.scheme, "lawn.example", c.listen, c.def); got != c.want {
			t.Errorf("smallURL(%q, %q) = %q, want %q", c.scheme, c.listen, got, c.want)
		}
	}
}
