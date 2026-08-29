// Package action implements the dashboard's privileged operations.
//
// This is the ONLY thing the web process may sudo. The dashboard runs
// unprivileged and cannot touch the firewall, the config or systemd directly —
// it pipes a JSON request here instead, and every field is re-validated in this
// process, as root, so a compromised web process cannot widen what it is
// allowed to ask for.
//
// Nothing from a request ever reaches a shell: every external command is
// invoked with an argument slice.
package action

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"strings"

	"github.com/am1nr/gateway/internal/config"
	"github.com/am1nr/gateway/internal/config/edit"
	"github.com/am1nr/gateway/internal/diag"
	"github.com/am1nr/gateway/internal/jsonx"
	"github.com/am1nr/gateway/internal/render"
	"github.com/am1nr/gateway/internal/share"
	"github.com/am1nr/gateway/internal/system"
	"github.com/am1nr/gateway/internal/webauth"
)

// Request is one privileged operation. Fields are flat because the protocol is
// a single JSON object on stdin; each handler reads only what it needs and
// validates it here rather than trusting the caller.
type Request struct {
	Action string `json:"action"`

	IP          string `json:"ip"`
	Name        string `json:"name"`
	Policy      string `json:"policy"`
	Schedule    string `json:"schedule"`
	Script      string `json:"script"`
	User        string `json:"user"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	Password    string `json:"password"`
	Unit        string `json:"unit"`
	Tag         string `json:"tag"`
	JSON        string `json:"json"`
	Link        string `json:"link"`
}

// Response is the result. ok is the only field the caller must consult.
type Response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	// Message is a short line suitable for showing to a person.
	Message string `json:"message,omitempty"`
	// PendingApply marks a change that is saved but not yet live.
	PendingApply bool `json:"pending_apply,omitempty"`
	// Data carries the action's payload.
	Data map[string]any `json:"data,omitempty"`
}

// Handler performs privileged actions.
type Handler struct {
	// Repo is the checkout root; Config is gateway.toml.
	Repo   string
	Config string
	// AuthFile holds the password hash. Empty means the installed location.
	AuthFile string
	// Root is the filesystem operated on. "/" in production.
	Root string
	// Systemd is used for unit restarts and status.
	Systemd system.Systemd
}

func fail(format string, a ...any) Response {
	return Response{OK: false, Error: fmt.Sprintf(format, a...)}
}

func ok(data map[string]any) Response {
	return Response{OK: true, Data: data}
}

// Handle dispatches one request. It never panics on bad input: this is the
// boundary, and the caller is assumed hostile.
func (h Handler) Handle(req Request) Response {
	switch req.Action {
	case "status":
		return h.status()
	case "clients":
		return h.clients()
	case "client_add":
		return h.clientAdd(req)
	case "client_rm":
		return h.clientRemove(req)
	case "jobs":
		return h.jobs()
	case "job_add":
		return h.jobAdd(req)
	case "job_rm":
		return h.jobRemove(req)
	case "job_toggle":
		return h.jobToggle(req)
	case "auth_status":
		return h.authStatus()
	case "verify_password":
		return h.verifyPassword(req)
	case "outbounds":
		return h.outbounds()
	case "import_link":
		return h.importLink(req)
	case "generated_config":
		return h.generatedConfig()
	case "restart_unit":
		return h.restartUnit(req)
	case "diff":
		return h.diff()
	case "apply":
		return h.applyNow()
	}
	return fail("unknown action: %q", req.Action)
}

// ---------------------------------------------------------------- status --

func (h Handler) status() Response {
	s := diag.Collector{Root: h.Root, Systemd: h.Systemd}.Collect()
	raw, err := json.Marshal(s)
	if err != nil {
		return fail("encoding the status: %v", err)
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return fail("encoding the status: %v", err)
	}
	return ok(data)
}

// --------------------------------------------------------------- clients --

// clientNameRE is deliberately narrower than what TOML would accept. The name
// is written into gateway.toml and displayed in a browser, so it holds no
// quotes, no newlines and no markup.
var clientNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,31}$`)

func (h Handler) clients() Response {
	list, err := edit.Clients(h.Config)
	if err != nil {
		return fail("could not read the client list: %v", err)
	}
	if list == nil {
		list = []edit.Client{}
	}
	data := map[string]any{"clients": list}

	// Policies come from the config, never from the request: the web process
	// must not be able to widen the set of policies it may assign.
	cfg, err := config.Load(h.Config)
	if err != nil {
		data["policies"] = config.BuiltinPolicies
		data["profiles"] = []string{}
		data["default_policy"] = "proxy"
		data["config_error"] = err.Error()
		return ok(data)
	}
	data["policies"] = cfg.Policies
	data["profiles"] = cfg.ProfileNames()
	data["default_policy"] = cfg.DefaultPolicy
	return ok(data)
}

// validIP re-checks an address against this config's LAN, as root.
func (h Handler) validIP(raw string) (string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("%q is not a valid IP address", raw)
	}
	cfg, err := config.Load(h.Config)
	if err != nil {
		return "", fmt.Errorf("the config does not load, so the address cannot be checked: %w", err)
	}
	if !cfg.LAN.Contains(addr) {
		return "", fmt.Errorf("%s is outside the LAN (%s)", addr, cfg.LANCidr)
	}
	if a := addr.String(); a == cfg.BoxIP || a == cfg.Router {
		return "", fmt.Errorf("%s is the gateway or the router itself", addr)
	}
	return addr.String(), nil
}

func (h Handler) validPolicy(raw string) (string, error) {
	cfg, err := config.Load(h.Config)
	if err != nil {
		return "", fmt.Errorf("the config does not load, so the policy cannot be checked: %w", err)
	}
	for _, p := range cfg.Policies {
		if p == raw {
			return raw, nil
		}
	}
	return "", fmt.Errorf("policy must be one of %s", strings.Join(cfg.Policies, ", "))
}

func (h Handler) clientAdd(req Request) Response {
	ip, err := h.validIP(req.IP)
	if err != nil {
		return fail("%v", err)
	}
	name := strings.TrimSpace(req.Name)
	if !clientNameRE.MatchString(name) {
		return fail("name must be 1-32 characters of letters, digits, space, dot, dash or underscore")
	}
	policy, err := h.validPolicy(req.Policy)
	if err != nil {
		return fail("%v", err)
	}

	if _, err := edit.AddClient(h.Config, edit.Client{IP: ip, Name: name, Policy: policy}); err != nil {
		return fail("could not add the client: %v", err)
	}
	if err := h.assertConfigStillLoads(); err != nil {
		return fail("%v", err)
	}
	return Response{
		OK:           true,
		Message:      fmt.Sprintf("%s (%s) set to %s", ip, name, policy),
		PendingApply: true,
	}
}

func (h Handler) clientRemove(req Request) Response {
	addr, err := netip.ParseAddr(strings.TrimSpace(req.IP))
	if err != nil {
		return fail("%q is not a valid IP address", req.IP)
	}
	if err := edit.RemoveClient(h.Config, addr.String()); err != nil {
		return fail("%v", err)
	}
	return Response{OK: true, Message: addr.String() + " removed", PendingApply: true}
}

// assertConfigStillLoads catches an edit that parses but does not validate,
// before apply does. Leaving a broken config behind means the next apply — or
// the next boot — fails for a reason nobody connects to this change.
func (h Handler) assertConfigStillLoads() error {
	if _, err := config.Load(h.Config); err != nil {
		return fmt.Errorf("the change was saved but the config no longer loads: %w", err)
	}
	return nil
}

// ------------------------------------------------------------------ jobs --

var (
	jobNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,23}$`)
	userRE    = regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`)
)

// maxScript bounds a job script. It is arbitrary bash run as root; the limit is
// there so a runaway paste cannot fill the config file.
const maxScript = 64 * 1024

func (h Handler) jobs() Response {
	list, err := edit.Jobs(h.Config)
	if err != nil {
		return fail("could not read the job list: %v", err)
	}
	if list == nil {
		list = []edit.Job{}
	}
	return ok(map[string]any{"jobs": list})
}

func (h Handler) jobAdd(req Request) Response {
	if !jobNameRE.MatchString(req.Name) {
		return fail("job name must be 1-24 characters of lowercase letters, digits or dashes")
	}
	if err := config.ValidateCron(req.Schedule); err != nil {
		return fail("%v", err)
	}
	if strings.TrimSpace(req.Script) == "" {
		return fail("the script is empty — nothing to run")
	}
	if len(req.Script) > maxScript {
		return fail("the script is too large (%d KB limit)", maxScript/1024)
	}
	user := req.User
	if user == "" {
		user = "root"
	}
	if !userRE.MatchString(user) {
		return fail("%q is not a valid user name", user)
	}
	description := req.Description
	if len(description) > 200 {
		description = description[:200]
	}

	if err := edit.SaveJob(h.Config, edit.Job{
		Name: req.Name, Schedule: req.Schedule, Script: req.Script,
		User: user, Enabled: true, Description: description,
	}); err != nil {
		return fail("could not save the job: %v", err)
	}
	if err := h.assertConfigStillLoads(); err != nil {
		return fail("%v", err)
	}
	return Response{OK: true, Message: "job " + req.Name + " saved", PendingApply: true}
}

func (h Handler) jobRemove(req Request) Response {
	if !jobNameRE.MatchString(req.Name) {
		return fail("job name must be 1-24 characters of lowercase letters, digits or dashes")
	}
	if err := edit.RemoveJob(h.Config, req.Name); err != nil {
		return fail("%v", err)
	}
	return Response{OK: true, Message: "job " + req.Name + " removed", PendingApply: true}
}

func (h Handler) jobToggle(req Request) Response {
	if !jobNameRE.MatchString(req.Name) {
		return fail("job name must be 1-24 characters of lowercase letters, digits or dashes")
	}
	if err := edit.ToggleJob(h.Config, req.Name, req.Enabled); err != nil {
		return fail("%v", err)
	}
	verb := "disabled"
	if req.Enabled {
		verb = "enabled"
	}
	return Response{OK: true, Message: "job " + req.Name + " " + verb, PendingApply: true}
}

// ------------------------------------------------------------------ auth --

func (h Handler) authStatus() Response {
	return ok(map[string]any{"password_set": webauth.LoadPassword(h.AuthFile) != nil})
}

// verifyPassword checks the password here, as root, so the hash never reaches
// the network-facing process. The password arrives on stdin, so it never
// appears in ps output.
//
// Rate limiting lives in the web app; this call is deliberately slow (scrypt)
// rather than clever.
func (h Handler) verifyPassword(req Request) Response {
	stored := webauth.LoadPassword(h.AuthFile)
	if stored == nil {
		return ok(map[string]any{"password_set": false, "valid": false})
	}
	return ok(map[string]any{
		"password_set": true,
		"valid":        webauth.VerifyPassword(req.Password, stored.Salt, stored.Hash),
	})
}

// -------------------------------------------------------------- outbounds --

func (h Handler) outbounds() Response {
	cfg, err := config.Load(h.Config)
	if err != nil {
		return fail("the config does not load: %v", err)
	}
	var list []map[string]any
	for _, ob := range cfg.AllOutbounds() {
		encoded, err := jsonx.EncodeIndented(ob.Object)
		if err != nil {
			return fail("encoding outbound %s: %v", ob.Tag, err)
		}
		list = append(list, map[string]any{
			"tag":         ob.Tag,
			"origin":      ob.Origin,
			"address":     ob.Address,
			"resolved_ip": ob.ResolvedIP,
			"json":        string(encoded),
		})
	}
	if list == nil {
		list = []map[string]any{}
	}
	return ok(map[string]any{"outbounds": list, "outbound_mark": cfg.OutboundMark})
}

// importLink turns a share link into outbound JSON. It writes nothing: the
// dashboard shows the result in the editor so it can be reviewed before it
// becomes the tunnel everything routes through.
func (h Handler) importLink(req Request) Response {
	res, err := share.Parse(req.Link)
	if err != nil {
		return fail("%v", err)
	}
	encoded, err := jsonx.EncodeIndented(res.Outbound)
	if err != nil {
		return fail("encoding the outbound: %v", err)
	}
	return ok(map[string]any{
		"json":     string(encoded),
		"name":     res.Name,
		"protocol": res.Protocol,
		"address":  res.Address,
		"port":     res.Port,
	})
}

func (h Handler) generatedConfig() Response {
	cfg, err := config.Load(h.Config)
	if err != nil {
		return fail("the config does not load: %v", err)
	}
	raw, err := render.RenderXray(cfg)
	if err != nil {
		return fail("%v", err)
	}
	return ok(map[string]any{"config": string(raw)})
}

// ----------------------------------------------------------------- units --

// restartable is the set of units the dashboard may restart. A whitelist rather
// than a pattern: this runs as root, and "restart any unit named by an HTTP
// request" is a different and much larger grant than it looks.
var restartable = map[string]bool{
	"xray.service":        true,
	"gw-network.service":  true,
	"AdGuardHome.service": true,
	"gw-web.service":      true,
	"gateway.target":      true,
}

func (h Handler) restartUnit(req Request) Response {
	if !restartable[req.Unit] {
		return fail("%q is not a unit this dashboard may restart", req.Unit)
	}
	if err := h.Systemd.Restart(req.Unit); err != nil {
		return fail("restarting %s: %v", req.Unit, err)
	}
	return Response{OK: true, Message: req.Unit + " restarted"}
}

// ---------------------------------------------------------------- runner --

// Run reads one request from r, handles it, and writes the response to w.
func (h Handler) Run(r io.Reader, w io.Writer) error {
	// Bounded: the request arrives over a pipe from a network-facing process.
	raw, err := io.ReadAll(io.LimitReader(r, maxScript+8*1024))
	if err != nil {
		return writeResponse(w, fail("could not read the request: %v", err))
	}
	var req Request
	if err := json.Unmarshal(raw, &req); err != nil {
		return writeResponse(w, fail("the request is not valid JSON"))
	}
	return writeResponse(w, h.Handle(req))
}

func writeResponse(w io.Writer, resp Response) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(resp)
}

// Must reports whether this process is root, which every caller requires.
func Must() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("the privileged helper must run as root (via the sudoers entry)")
	}
	return nil
}

// SetPassword writes the dashboard password. Used by `gw web-passwd`, which
// runs as root for the same reason this helper does: the hash file is
// 0600 root:root and the web process must never be able to read it.
func SetPassword(path, password string) error {
	return webauth.SavePassword(path, password)
}
