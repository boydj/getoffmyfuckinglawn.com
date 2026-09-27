package shame

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/logstore"
	"github.com/boydj/getoffmyfuckinglawn.com/web"
)

func TestUserTriggeredFetchers(t *testing.T) {
	s := openStore(t)
	var f fx
	chat := "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot"
	gpt := "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; +https://openai.com/gptbot"
	// Verified ChatGPT-User (exempt) with /lawn/ hits.
	f.lawn("20.0.0.1", chat, 8075, "MICROSOFT", time.Hour, time.Minute, 0, 100, "/lawn/a")
	f.id("20.0.0.1", chat, "OpenAI", logstore.StatusVerified)
	// Spoofed ChatGPT-User: the exemption must not apply to a false claim.
	f.lawn("198.51.100.66", chat, 64501, "HOSTING-AS", time.Hour, time.Minute, 0, 100, "/lawn/b")
	f.id("198.51.100.66", chat, "OpenAI", logstore.StatusSpoofed)
	// Verified GPTBot (not exempt).
	f.lawn("20.0.0.2", gpt, 8075, "MICROSOFT", time.Hour, time.Minute, 0, 100, "/lawn/c")
	f.id("20.0.0.2", gpt, "OpenAI", logstore.StatusVerified)
	f.load(t, s)

	opt := testOptions(t, s)
	opt.Templates = web.Templates("")
	opt.BlocklistMin = 1
	opt.RobotsExempt = func(ua string) bool { return strings.Contains(ua, "ChatGPT-User") }
	r, err := Build(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.UserTriggered) != 1 || r.UserTriggered[0].Name != "OpenAI" || r.UserTriggered[0].W[WAll].Pages != 1 {
		t.Fatalf("user-triggered section: %+v", r.UserTriggered)
	}
	if len(r.Verified) != 1 || r.Verified[0].W[WAll].Pages != 1 {
		t.Errorf("GPTBot must remain a verified offender alone: %+v", r.Verified)
	}
	if len(r.Liars) != 1 {
		t.Errorf("spoofed ChatGPT-User must stay in the Hall of Liars: %+v", r.Liars)
	}
	for _, g := range r.ASNs {
		for _, m := range g.Members {
			if m.Kind == StatusUserTriggered {
				t.Errorf("user-initiated fetchers must not be in Top ASNs: %+v", g)
			}
		}
	}
	if r.Totals[WAll].Pages != 3 {
		t.Errorf("totals still count every held request: %d", r.Totals[WAll].Pages)
	}
	for _, c := range r.Blocklist {
		if strings.HasPrefix(c, "20.0.0.1") {
			t.Errorf("user-initiated fetcher in blocklist: %v", r.Blocklist)
		}
	}
	var sawFeed bool
	for _, e := range r.Feed {
		if e.Status == StatusUserTriggered {
			sawFeed = true
			for _, c := range e.CIDRs {
				if strings.HasSuffix(c, "/32") {
					t.Errorf("user-initiated feed entry publishes a host address: %v", e.CIDRs)
				}
			}
		}
	}
	if !sawFeed {
		t.Error("feed.json should list the user-initiated fetcher with its status")
	}
	idx, err := os.ReadFile(filepath.Join(opt.PublicDir, "shame", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(idx), `id="user-initiated"`) || !strings.Contains(string(idx), "verified, user-initiated") {
		t.Error("index page lacks the user-initiated section or badge")
	}

	// Without the exemption hook everything is a plain verified offender.
	opt.RobotsExempt = nil
	opt.PublicDir = t.TempDir()
	r2, err := Collect(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if len(r2.UserTriggered) != 0 || r2.Verified[0].W[WAll].Pages != 2 {
		t.Errorf("nil RobotsExempt must exempt nobody: %+v", r2.Verified)
	}
}
