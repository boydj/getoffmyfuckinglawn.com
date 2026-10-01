// Command caddy is Caddy with the plugins lawn needs: the standard modules
// plus JA4 TLS fingerprinting (package caddyja4). Built by `make
// build-caddy` and installed on the host in place of the packaged binary
// (see deploy/host-setup.sh).
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	_ "github.com/boydj/getoffmyfuckinglawn.com/caddy/caddyja4"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

func main() { caddycmd.Main() }
