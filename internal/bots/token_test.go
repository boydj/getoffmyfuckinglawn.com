package bots

import "testing"

func TestToken(t *testing.T) {
	cases := []struct {
		ua, want string
		bot      bool
	}{
		{"Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)", "GPTBot", true},
		{"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)", "ClaudeBot", true},
		{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "Googlebot", true},
		{"Mozilla/5.0 (Linux; Android 6.0.1) AppleWebKit/537.36 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", "bingbot", true},
		{"meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)", "meta-externalagent", true},
		{"Mozilla/5.0 (compatible; NewShinyCrawler/0.1; +https://newshiny.example/crawler)", "NewShinyCrawler", true},
		{"Scrapy/2.11 (+https://scrapy.org)", "scrapy", true},
		{"python-requests/2.31.0", "python-requests", true},
		{"curl/8.5.0", "curl", true},
		{"Go-http-client/1.1", "go-http-client", true},
		{"SomeTool/3.0", "SomeTool", true},
		{"", "(empty user agent)", true},
		{"Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0", "", false},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15", "", false},
	}
	for _, c := range cases {
		got, bot := Token(c.ua)
		if got != c.want || bot != c.bot {
			t.Errorf("Token(%q) = %q,%v want %q,%v", c.ua, got, bot, c.want, c.bot)
		}
	}
}

func TestContactAndDomain(t *testing.T) {
	if c := Contact("Mozilla/5.0 (compatible; X/1; +https://x.example/bot.html)"); c != "https://x.example/bot.html" {
		t.Errorf("url contact: %q", c)
	}
	if c := Contact("ClaudeBot/1.0; +claudebot@anthropic.com"); c != "claudebot@anthropic.com" {
		t.Errorf("mail contact: %q", c)
	}
	if c := Contact("curl/8"); c != "" {
		t.Errorf("no contact: %q", c)
	}
	for in, want := range map[string]string{
		"crawl-66-249-66-1.googlebot.com.": "googlebot.com",
		"example.com":                      "example.com",
		"":                                 "",
		"host":                             "host",
	} {
		if got := Domain(in); got != want {
			t.Errorf("Domain(%q)=%q want %q", in, got, want)
		}
	}
}
