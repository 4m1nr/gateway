// Package gateway holds the assets the gw binary carries with it.
//
// The templates live at the repo root rather than under internal/render so
// that lib/render.py, tests/run.sh and the CI shell-lint job keep reading the
// same files during the migration — one copy, several readers. go:embed can
// only reach downward from its own package directory, which is why this file
// sits at the module root.
package gateway

import "embed"

// Templates is the nftables, systemd, sysctl and helper-script source the
// renderer substitutes into. Embedding it means a gw binary renders a complete
// build tree without the repo checked out beside it.
//
//go:embed templates
var Templates embed.FS

// Dashboard is the built web dashboard: the Vite output, committed so a
// checkout builds without Node and so the running service has no dependency on
// the repo being present. gw-web runs as gwweb under ProtectSystem=strict, and
// a service that cannot read its own assets is a dashboard that fails exactly
// when it is needed.
//
//go:embed all:dashboard/dist
var Dashboard embed.FS
