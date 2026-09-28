package server

import (
	"strings"
	"testing"

	"github.com/boydj/getoffmyfuckinglawn.com/web"
)

func TestRenderHome(t *testing.T) {
	b, err := RenderHome(web.Templates(""), HomeData{RobotsTxt: RobotsTxt, Bait: []string{"/lawn/aaa", "/lawn/archive/bbb"}})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		`id="methodology"`,
		`<a href="/lawn/aaa" rel="nofollow" tabindex="-1">`,
		`aria-hidden="true"`,
		"User-agent: *\nDisallow: /lawn/",
		`href="/shame/"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("homepage missing %q", want)
		}
	}
	if strings.Contains(strings.ToLower(s), "<script") {
		t.Error("homepage must not contain JS")
	}
	if len(b) > 50<<10 {
		t.Errorf("homepage is %d bytes, want < 50KB", len(b))
	}
}

func TestRenderHomeMirrors(t *testing.T) {
	b, err := RenderHome(web.Templates(""), HomeData{RobotsTxt: RobotsTxt, Gopher: "gopher://lawn.example/", Gemini: "gemini://lawn.example/"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`<a href="gopher://lawn.example/"><code>gopher://lawn.example/</code></a> and <a href="gemini://lawn.example/">`,
		"Gopher or Gemini"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("homepage missing %q", want)
		}
	}
	if strings.Contains(string(b), "ZgotmplZ") {
		t.Error("html/template refused the small-web links")
	}
	b, _ = RenderHome(web.Templates(""), HomeData{RobotsTxt: RobotsTxt})
	if strings.Contains(string(b), "small web") {
		t.Error("no mirrors configured: nothing to advertise")
	}
}
