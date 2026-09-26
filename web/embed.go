// Package web embeds the HTML templates so the binary is self-contained.
// Set templates_dir in config to load them from disk instead.
package web

import (
	"embed"
	"io/fs"
	"os"
)

//go:embed templates
var embedded embed.FS

// Templates returns the template filesystem rooted at templates/. If dir is
// non-empty it is used instead of the embedded copy.
func Templates(dir string) fs.FS {
	if dir != "" {
		return os.DirFS(dir)
	}
	sub, err := fs.Sub(embedded, "templates")
	if err != nil {
		panic(err) // unreachable: the directory is embedded at build time
	}
	return sub
}
