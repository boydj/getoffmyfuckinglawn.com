# getoffmyfuckinglawn.com: single entry point. `make` lists the targets.

SHELL         := bash
.SHELLFLAGS   := -eu -o pipefail -c
.DEFAULT_GOAL := help
MAKEFLAGS     += --no-print-directory

GO      ?= go
TOFU    ?= tofu
INFRA   := infra
DIST    := dist
BIN     := $(DIST)/lawn
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

# The race detector needs cgo; fall back to plain tests without a C compiler.
RACE ?= $(if $(shell command -v $${CC:-cc} 2>/dev/null),-race,)
# `integration` is a no-op unless tests use that build tag; it makes sure
# tag-gated integration tests always run as part of `make test`.
TEST_TAGS ?= integration

# Deploy target. Defaults come from OpenTofu outputs when state exists;
# set DEPLOY_HOST (and LAWN_DOMAIN on a non-OpenTofu host) to override.
# tf_out reads one OpenTofu output, or nothing (no state, no tofu, or tofu
# printing a warning instead of a value).
tf_out = $(shell v="$$($(TOFU) -chdir=$(INFRA) output -no-color -raw $(1) 2>/dev/null)" && [[ "$$v" =~ ^[A-Za-z0-9.:-]+$$ ]] && printf '%s' "$$v")
DEPLOY_USER ?= root
DEPLOY_HOST ?= $(call tf_out,ipv4)
LAWN_DOMAIN ?= $(call tf_out,domain)
SSH_KEY     ?=
SSH_PORT    ?= 22
SUDO        := $(if $(filter root,$(DEPLOY_USER)),,sudo -n)
SSH_OPTS    := -p $(SSH_PORT) -o StrictHostKeyChecking=accept-new $(if $(SSH_KEY),-i $(SSH_KEY) -o IdentitiesOnly=yes,)

# Local dev (`make run`): throwaway state under data/dev (gitignored).
DEV_DIR := data/dev

.PHONY: help test vet vulncheck lint fmt build build-linux infra plan validate deploy \
	logs ssh patch-status destroy loadtest run clean require-host

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "; printf "Usage: make <target>\n\n"} \
		/^[a-zA-Z_-]+:.*## / {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

## ---------------------------------------------------------------- Go

test: ## Unit + integration tests (race detector when cgo is available)
	$(GO) test $(RACE) -count=1 -tags '$(TEST_TAGS)' ./...

vet: ## go vet + staticcheck
	$(GO) vet -tags '$(TEST_TAGS)' ./...
	staticcheck -tags '$(TEST_TAGS)' ./...

# govulncheck must judge the standard library of the toolchain that builds the
# release binary, i.e. go.mod's toolchain line, not whatever go is on PATH.
GO_TOOLCHAIN := $(shell $(GO) mod edit -json 2>/dev/null | sed -n 's/.*"Toolchain": "\(.*\)".*/\1/p')

vulncheck: ## govulncheck: known vulnerabilities in the Go toolchain and modules we call
	GOTOOLCHAIN=$(or $(GO_TOOLCHAIN),auto) $(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

lint: vet ## vet + gofmt, shellcheck, tofu fmt
	@out="$$(gofmt -l $$(git ls-files -co --exclude-standard '*.go'))"; \
		if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	@if command -v shellcheck >/dev/null; then shellcheck -x deploy/*.sh $$(ls tools/*.sh 2>/dev/null); \
		else echo "shellcheck not installed; skipping"; fi
	@if command -v $(TOFU) >/dev/null; then $(TOFU) -chdir=$(INFRA) fmt -check -recursive; \
		else echo "$(TOFU) not installed; skipping"; fi

fmt: ## gofmt + tofu fmt in place
	gofmt -w $$(git ls-files -co --exclude-standard '*.go')
	$(TOFU) -chdir=$(INFRA) fmt -recursive

build: ## Build for this machine into bin/lawn
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/lawn ./cmd/lawn

build-linux: ## Static linux/amd64 release binary into dist/lawn
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/lawn

## ---------------------------------------------------------------- Infra

infra: ## tofu init + apply (needs VULTR_API_KEY and infra/terraform.tfvars)
	@test -n "$${VULTR_API_KEY:-}" || { echo "VULTR_API_KEY is not set"; exit 1; }
	@test -f $(INFRA)/terraform.tfvars || { echo "copy infra/terraform.tfvars.example to infra/terraform.tfvars first"; exit 1; }
	$(TOFU) -chdir=$(INFRA) init -input=false
	$(TOFU) -chdir=$(INFRA) apply
	@echo; echo "Next: point the domain's nameservers at ns1.vultr.com / ns2.vultr.com, then: make deploy"

plan: ## tofu init + plan
	$(TOFU) -chdir=$(INFRA) init -input=false
	$(TOFU) -chdir=$(INFRA) plan

validate: ## tofu fmt -check + validate (no credentials needed)
	$(TOFU) -chdir=$(INFRA) fmt -check -recursive
	$(TOFU) -chdir=$(INFRA) init -backend=false -input=false >/dev/null
	$(TOFU) -chdir=$(INFRA) validate

destroy: ## tofu destroy: deletes the instance, firewall, SSH key and DNS zone
	$(TOFU) -chdir=$(INFRA) destroy

## ---------------------------------------------------------------- Host

require-host:
	@test -n "$(DEPLOY_HOST)" || { echo "DEPLOY_HOST is empty: run 'make infra' first or set DEPLOY_HOST=<ip>"; exit 1; }

deploy: require-host build-linux ## Build, ship to the host over SSH, restart, health-check
	DEPLOY_HOST='$(DEPLOY_HOST)' DEPLOY_USER='$(DEPLOY_USER)' SSH_KEY='$(SSH_KEY)' \
		SSH_PORT='$(SSH_PORT)' LAWN_DOMAIN='$(LAWN_DOMAIN)' LAWN_BINARY='$(BIN)' \
		deploy/deploy.sh

logs: require-host ## Follow the lawn journal on the host
	ssh $(SSH_OPTS) $(DEPLOY_USER)@$(DEPLOY_HOST) journalctl -u lawn -f

ssh: require-host ## Shell on the host
	ssh $(SSH_OPTS) $(DEPLOY_USER)@$(DEPLOY_HOST)

patch-status: require-host ## Host patch state: pending updates, kernel, reboot needed, failed units
	ssh $(SSH_OPTS) $(DEPLOY_USER)@$(DEPLOY_HOST) /usr/local/lib/lawn/patch-status.sh

onion-address: require-host ## Print the Tor onion mirror's address
	ssh $(SSH_OPTS) $(DEPLOY_USER)@$(DEPLOY_HOST) $(SUDO) cat /var/lib/tor/lawn/hostname

onion-backup: require-host ## Copy the onion service's keys off the host to onion-keys.tar.gz (secret; gitignored)
	@umask 077; ssh $(SSH_OPTS) $(DEPLOY_USER)@$(DEPLOY_HOST) $(SUDO) tar -C /var/lib/tor -czf - lawn >onion-keys.tar.gz.tmp
	@mv -f onion-keys.tar.gz.tmp onion-keys.tar.gz
	@echo "wrote onion-keys.tar.gz: the onion address's private key. Keep it somewhere safe and never commit it."

## ---------------------------------------------------------------- Dev

loadtest: ## Run the load test (tools/); pass options via LOADTEST_ARGS
	@if [ -x tools/loadtest.sh ]; then tools/loadtest.sh $(LOADTEST_ARGS); \
		else $(GO) run ./tools/loadtest $(LOADTEST_ARGS); fi

run: ## Serve locally on 127.0.0.1:8080 with throwaway state in data/dev
	@mkdir -p $(DEV_DIR)/public $(DEV_DIR)/ranges
	LAWN_SECRET="$${LAWN_SECRET:-$$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')}" \
	LAWN_BASE_URL=http://127.0.0.1:8080 \
	LAWN_DB_PATH=$(DEV_DIR)/lawn.db \
	LAWN_ASN_DB_PATH=$(DEV_DIR)/ip2asn-combined.tsv.gz \
	LAWN_PUBLIC_DIR=$(DEV_DIR)/public \
	LAWN_RANGES_CACHE_DIR=$(DEV_DIR)/ranges \
	LAWN_CORPUS_DIR=corpus \
	LAWN_CRAWLERS_FILE=config/crawlers.yaml \
	LAWN_TEMPLATES_DIR=web/templates \
		$(GO) run ./cmd/lawn serve -config config/config.example.yaml

clean: ## Remove build output
	rm -rf $(DIST) bin
