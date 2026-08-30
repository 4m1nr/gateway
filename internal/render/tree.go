package render

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	gateway "github.com/am1nr/gateway"
	"github.com/am1nr/gateway/internal/config"
	"github.com/am1nr/gateway/internal/jsonx"
)

// executable are the files installed with the execute bit.
//
// Job scripts are handled separately: they run as root and may hold
// credentials, so they are 0700 rather than 0755. net.sh is deliberately absent
// — it is only ever sourced, never executed, and bin/gw's
// `usr/local/lib/gateway/*.sh` glob used to make it 0755 by accident, the same
// over-broad-glob mistake that once made job scripts world-readable.
var executable = map[string]bool{
	"usr/local/lib/gateway/ip-rules.sh":       true,
	"usr/local/lib/gateway/health.sh":         true,
	"usr/local/lib/gateway/ts-bypass.sh":      true,
	"usr/local/lib/gateway/xray-update.sh":    true,
	"usr/local/lib/gateway/adguard-update.sh": true,
	"usr/local/lib/gateway/web-action.py":     true,
}

const jobScriptPrefix = "usr/local/lib/gateway/jobs/"

// sudoersPath must be installed 0440. sudo refuses to read a sudoers file it
// considers too permissive, and 0644 additionally exposes the grant to every
// user on the box. The Python renderer staged this 0644 and bin/gw re-set it to
// 0440 at install time; defining it once here is what stops the two drifting.
const sudoersPath = "etc/sudoers.d/gw-web"

// File is one rendered file destined for the staging tree.
type File struct {
	// Path is relative to the tree root and mirrors the target filesystem.
	Path    string
	Content string
	Mode    os.FileMode
}

// Options tune what Build produces. The zero value is fine for tests.
type Options struct {
	// Repo is the path recorded in the generated env file and systemd units,
	// so units invoke the binary from where it actually lives.
	Repo string
	// GeneratedAt is stamped into the nftables header. Fixed in tests so
	// output is reproducible.
	GeneratedAt time.Time
}

// Build renders every file the gateway installs.
//
// The result mirrors the target filesystem, so `gw diff` can compare it against
// / path for path and `gw apply` can install it with no translation step. Two
// entries are not filesystem-shaped and are consumed by apply directly:
// adguard-overrides.json and tailscale-args.
func Build(c *config.Config, opt Options) ([]File, error) {
	if opt.GeneratedAt.IsZero() {
		opt.GeneratedAt = time.Now()
	}

	contents := map[string]string{}

	nft, err := NFT(c, opt.GeneratedAt)
	if err != nil {
		return nil, err
	}
	contents["etc/nftables.d/gateway.nft"] = nft

	sysctl, err := Sysctl(c)
	if err != nil {
		return nil, err
	}
	contents["etc/sysctl.d/99-gateway.conf"] = sysctl

	network, err := Network(c)
	if err != nil {
		return nil, err
	}
	contents["etc/systemd/network/10-gateway-wan.network"] = network

	xray, err := RenderXray(c)
	if err != nil {
		return nil, err
	}
	contents["usr/local/etc/xray/config.json"] = string(xray)

	env, err := Env(c, opt.Repo)
	if err != nil {
		return nil, err
	}
	contents["usr/local/lib/gateway/env"] = env

	for _, name := range []string{"ip-rules.sh", "health.sh",
		"ts-bypass.sh", "net.sh", "xray-update.sh", "adguard-update.sh"} {
		text, err := templateFile("lib/" + name)
		if err != nil {
			return nil, err
		}
		contents["usr/local/lib/gateway/"+name] = text
	}

	jobs, err := Jobs(c)
	if err != nil {
		return nil, err
	}
	for path, text := range jobs {
		contents[path] = text
	}

	if c.WebEnabled {
		// The privileged helper is not rendered: it is a copy of the gw binary
		// itself, installed root-owned at /usr/local/lib/gateway/gw-action by
		// apply. The dashboard's assets are not rendered either — they are
		// embedded in the binary, so gw-web serves them without depending on
		// the repo being readable.
		//
		// Deliberately contains no secrets: the password hash lives in
		// /etc/gateway/web-auth.json, 0600 root:root, and is never rendered.
		settings, err := jsonx.EncodeIndented(obj(
			"listen", c.WebListen,
			"port", num(c.WebPort),
			"tls", c.WebTLS,
			"cert", c.WebCert,
			"key", c.WebKey,
			"allow_cidrs", strs(c.WebAllow),
			"session_hours", num(c.SessionHours),
			"max_failed_logins", num(c.MaxFailedLogins),
			"lockout_minutes", num(c.LockoutMinutes),
		))
		if err != nil {
			return nil, err
		}
		contents["etc/gateway/web.json"] = string(settings)

		sudoers, err := templateFile("sudoers.gw-web")
		if err != nil {
			return nil, err
		}
		contents["etc/sudoers.d/gw-web"] = sudoers
	}

	units, err := fs.ReadDir(gateway.Templates, "templates/systemd")
	if err != nil {
		return nil, err
	}
	for _, u := range units {
		name := u.Name()
		switch {
		case name == "gw-tailscale-exception.service" && (c.TSRouteControl || !c.TSEnabled):
			continue
		case name == "gw-web.service" && !c.WebEnabled:
			continue
		case strings.HasPrefix(name, "gw-update.") && c.AutoUpdate == "off":
			continue
		}
		text, err := templateFile("systemd/" + name)
		if err != nil {
			return nil, err
		}
		if strings.Contains(text, "{{") {
			text, err = subst(text, map[string]string{
				"HEALTH_INTERVAL":        strconv.Itoa(c.HealthInterval),
				"TARGET_WANTS":           TargetWants(c),
				"REPO":                   opt.Repo,
				"AUTO_UPDATE_MODE":       c.AutoUpdate,
				"AUTO_UPDATE_ONCALENDAR": c.AutoUpdateSchedule,
			})
			if err != nil {
				return nil, err
			}
		}
		contents["etc/systemd/system/"+name] = text
	}

	// AdGuard installs its own unit, so it is extended rather than replaced.
	dropin, err := templateFile("systemd-dropin/adguard-gw.conf")
	if err != nil {
		return nil, err
	}
	contents["etc/systemd/system/AdGuardHome.service.d/gw.conf"] = dropin

	if c.TSEnabled && !c.TSRouteControl {
		text, err := templateFile("systemd-dropin/tailscaled-gw-exception.conf")
		if err != nil {
			return nil, err
		}
		contents["etc/systemd/system/tailscaled.service.d/gw-exception.conf"] = text
	}

	// Not filesystem-shaped: consumed by `gw apply` at install time.
	overrides, err := jsonx.EncodeIndented(AdGuardOverrides(c))
	if err != nil {
		return nil, err
	}
	contents["adguard-overrides.json"] = string(overrides)
	contents["tailscale-args"] = TailscaleArgs(c)

	paths := make([]string, 0, len(contents))
	for p := range contents {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	out := make([]File, 0, len(paths))
	for _, p := range paths {
		out = append(out, File{Path: p, Content: contents[p], Mode: modeFor(p)})
	}
	return out, nil
}

func modeFor(rel string) os.FileMode {
	switch {
	case strings.HasPrefix(rel, jobScriptPrefix):
		// Job scripts run as root and may hold credentials.
		return 0o700
	case rel == sudoersPath:
		return 0o440
	case executable[rel]:
		return 0o755
	default:
		return 0o644
	}
}

// Write renders into a staging directory, replacing whatever was there.
//
// The tree is staging only: `gw diff` compares it against / and `gw apply`
// installs from it, so writing here changes nothing about a running gateway.
func Write(c *config.Config, out string, opt Options) ([]File, error) {
	files, err := Build(c, opt)
	if err != nil {
		return nil, err
	}
	if err := os.RemoveAll(out); err != nil {
		return nil, fmt.Errorf("clearing %s: %w", out, err)
	}
	for _, f := range files {
		path := filepath.Join(out, f.Path)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, []byte(f.Content), f.Mode); err != nil {
			return nil, err
		}
		// WriteFile applies the mode only when it creates the file, and umask
		// masks it either way; chmod is what actually pins 0700 on a job script.
		if err := os.Chmod(path, f.Mode); err != nil {
			return nil, err
		}
	}
	return files, nil
}

// NotInstalled are rendered entries that `gw apply` consumes directly rather
// than copying into the filesystem. They live in the staging tree because that
// is where apply looks for them, but they have no place on the box.
var NotInstalled = map[string]bool{
	"adguard-overrides.json": true,
	"tailscale-args":         true,
}

// Installed reports whether this file is copied onto the target filesystem.
func (f File) Installed() bool { return !NotInstalled[f.Path] }
