package main

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenRobots(t *testing.T) {
	var out, errb bytes.Buffer
	if err := run([]string{"gen-robots", "-config", ""}, &out, &errb); err != nil {
		t.Fatal(err)
	}
	if out.String() != "User-agent: *\nDisallow: /lawn/\n" {
		t.Fatalf("got %q", out.String())
	}
}

func TestUsageAndUnknown(t *testing.T) {
	var out, errb bytes.Buffer
	if err := run(nil, &out, &errb); !errors.Is(err, flag.ErrHelp) || !strings.Contains(errb.String(), "usage") {
		t.Fatalf("no-args: %v %q", err, errb.String())
	}
	if err := run([]string{"frobnicate", "-config", ""}, &out, &errb); err == nil {
		t.Fatal("unknown command should fail")
	}
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	os.WriteFile(bad, []byte("drip: { chunk_bytes: -1 }\n"), 0o600)
	if err := run([]string{"gen-robots", "-config", bad}, &out, &errb); err == nil {
		t.Fatal("gen-robots should reject an invalid config")
	}
}

func TestBuildShameAndStats(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("LAWN_DB_PATH", filepath.Join(dir, "lawn.db"))
	t.Setenv("LAWN_PUBLIC_DIR", filepath.Join(dir, "public"))
	var out, errb bytes.Buffer
	if err := run([]string{"build-shame", "-config", ""}, &out, &errb); err != nil {
		t.Fatalf("build-shame: %v (%s)", err, errb.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "public", "shame", "index.html")); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run([]string{"stats", "-config", "", "--since", "7d"}, &out, &errb); err != nil {
		t.Fatalf("stats: %v", err)
	}
	if err := run([]string{"stats", "-config", "", "--since", "3h"}, &out, &errb); err == nil {
		t.Fatal("stats should reject an unsupported window")
	}
}
