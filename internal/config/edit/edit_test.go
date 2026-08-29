package edit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tempConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gateway.toml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func read(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

const withComments = `# The gateway's source of truth.
[net]
wan_if = "eth0"    # the only NIC

# Devices listed here override the default.
[[client]]
ip     = "192.168.1.60"
name   = "tv"
policy = "direct"
`

// The config is a file a person reads. Editing a client must not disturb a
// single comment or blank line elsewhere.
func TestAddClientPreservesTheRestOfTheFile(t *testing.T) {
	path := tempConfig(t, withComments)
	if _, err := AddClient(path, Client{IP: "192.168.1.50", Name: "laptop", Policy: "proxy"}); err != nil {
		t.Fatal(err)
	}
	got := read(t, path)
	for _, want := range []string{
		"# The gateway's source of truth.",
		`wan_if = "eth0"    # the only NIC`,
		"# Devices listed here override the default.",
		`ip     = "192.168.1.60"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("editing dropped %q:\n%s", want, got)
		}
	}
	clients, err := Clients(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 2 {
		t.Fatalf("got %d clients, want 2: %+v", len(clients), clients)
	}
}

// Adding an address that is already listed replaces it. Appending instead would
// leave two entries for one device, and which one wins is not visible.
func TestAddClientReplacesRatherThanDuplicating(t *testing.T) {
	path := tempConfig(t, withComments)
	replaced, err := AddClient(path, Client{IP: "192.168.1.60", Name: "tv", Policy: "block"})
	if err != nil {
		t.Fatal(err)
	}
	if replaced != "direct" {
		t.Errorf("replaced policy reported as %q, want direct", replaced)
	}
	clients, _ := Clients(path)
	if len(clients) != 1 {
		t.Fatalf("got %d entries for one address: %+v", len(clients), clients)
	}
	if clients[0].Policy != "block" {
		t.Errorf("policy is %q, want block", clients[0].Policy)
	}
}

// Profile names contain hyphens. A \w-based pattern silently fails to match
// them, which once made profile clients invisible to list and rm, and made add
// duplicate instead of replace.
func TestHyphenatedProfileClientsAreVisible(t *testing.T) {
	path := tempConfig(t, withComments)
	if _, err := AddClient(path, Client{IP: "192.168.1.70", Name: "work laptop", Policy: "work-laptop"}); err != nil {
		t.Fatal(err)
	}
	clients, _ := Clients(path)
	found := false
	for _, c := range clients {
		if c.IP == "192.168.1.70" {
			found = true
			if c.Policy != "work-laptop" {
				t.Errorf("policy read back as %q", c.Policy)
			}
		}
	}
	if !found {
		t.Fatal("a client with a hyphenated profile policy is invisible to Clients()")
	}
	if _, err := AddClient(path, Client{IP: "192.168.1.70", Name: "work laptop", Policy: "proxy"}); err != nil {
		t.Fatal(err)
	}
	if clients, _ = Clients(path); len(clients) != 2 {
		t.Errorf("re-adding a hyphenated-policy client duplicated it: %+v", clients)
	}
}

func TestRemoveClient(t *testing.T) {
	path := tempConfig(t, withComments)
	if err := RemoveClient(path, "192.168.1.60"); err != nil {
		t.Fatal(err)
	}
	if clients, _ := Clients(path); len(clients) != 0 {
		t.Errorf("client still present: %+v", clients)
	}
	// Removing something absent must say so, or a typo looks like it worked.
	if err := RemoveClient(path, "192.168.1.99"); err == nil {
		t.Error("removing an unlisted client reported success")
	}
}

func TestClientsAreSortedByAddress(t *testing.T) {
	path := tempConfig(t, "[net]\n")
	for _, ip := range []string{"192.168.1.100", "192.168.1.9", "192.168.1.20"} {
		if _, err := AddClient(path, Client{IP: ip, Name: "d", Policy: "proxy"}); err != nil {
			t.Fatal(err)
		}
	}
	clients, _ := Clients(path)
	want := []string{"192.168.1.9", "192.168.1.20", "192.168.1.100"}
	for i, c := range clients {
		if c.IP != want[i] {
			t.Errorf("sorted as %v, want %v", clientIPs(clients), want)
			break
		}
	}
}

func clientIPs(cs []Client) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.IP
	}
	return out
}

// A name carrying a quote would break out of the TOML string and produce a file
// that no longer parses — from the dashboard, that is arbitrary config
// injection.
func TestClientNameCannotEscapeItsString(t *testing.T) {
	path := tempConfig(t, "[net]\n")
	if _, err := AddClient(path, Client{IP: "192.168.1.5", Name: `evil"` + "\npolicy = \"block", Policy: "proxy"}); err == nil {
		t.Fatal("a name containing a quote and a newline was accepted")
	}
}

// ------------------------------------------------------------------- jobs --

const withHandWrittenJob = `[net]
wan_if = "eth0"

# Written by hand, and not managed by the tool.
[[job]]
name     = "handmade"
schedule = "@daily"
script   = '''
echo hello
'''
`

func TestSaveJobCreatesAndReusesTheRegion(t *testing.T) {
	path := tempConfig(t, withHandWrittenJob)
	err := SaveJob(path, Job{
		Name: "backup", Schedule: "0 4 * * *", User: "root", Enabled: true,
		Description: "config backup", Script: "tar -czf /tmp/gw.tgz /opt/gateway\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := read(t, path)
	if strings.Count(got, jobsBegin) != 1 || strings.Count(got, jobsEnd) != 1 {
		t.Fatalf("the managed region is malformed:\n%s", got)
	}
	if !strings.Contains(got, "# Written by hand, and not managed by the tool.") {
		t.Error("the hand-written job's comment was lost")
	}

	jobs, err := Jobs(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 {
		t.Fatalf("got %d jobs, want 2: %+v", len(jobs), jobs)
	}
	for _, j := range jobs {
		switch j.Name {
		case "handmade":
			if j.Managed {
				t.Error("a hand-written job is reported as managed")
			}
		case "backup":
			if !j.Managed {
				t.Error("a job this tool wrote is not reported as managed")
			}
		}
	}

	// A second save must reuse the region, not append another one.
	if err := SaveJob(path, Job{Name: "second", Schedule: "@hourly", Script: "true\n", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if got = read(t, path); strings.Count(got, jobsBegin) != 1 {
		t.Errorf("a second managed region was created:\n%s", got)
	}
}

// The script is stored as a TOML literal string. The double-quoted kind
// processes escapes, so a bash line continuation would be collapsed and \n
// would become a real newline — quietly rewriting the script between what you
// wrote and what runs.
func TestScriptSurvivesBackslashesVerbatim(t *testing.T) {
	script := "curl -sS \\\n  --max-time 5 \\\n  https://example.com\n" +
		`printf 'a\nb\n'` + "\n"
	path := tempConfig(t, "[net]\n")
	if err := SaveJob(path, Job{Name: "probe", Schedule: "@hourly", Script: script, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	jobs, err := Jobs(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 {
		t.Fatalf("got %d jobs", len(jobs))
	}
	// TOML trims the newline that follows the opening ''', so the stored
	// value differs from the input by at most a trailing newline. Everything
	// inside it — backslash continuations, literal \n — must be untouched.
	if got, want := strings.TrimRight(jobs[0].Script, "\n"), strings.TrimRight(script, "\n"); got != want {
		t.Errorf("the script was rewritten in storage:\n got %q\nwant %q", got, want)
	}

	// Saving what was loaded must not drift. Without this, a dashboard that
	// reads a job and writes it back unchanged would grow or shrink the script
	// by a newline on every save.
	if err := SaveJob(path, jobs[0]); err != nil {
		t.Fatal(err)
	}
	again, err := Jobs(path)
	if err != nil {
		t.Fatal(err)
	}
	if again[0].Script != jobs[0].Script {
		t.Errorf("a save/load round trip is not stable:\n first %q\nsecond %q",
			jobs[0].Script, again[0].Script)
	}
}

// ”' terminates a TOML literal string, so a script containing one would break
// out of its own value and inject TOML.
func TestScriptCannotTerminateItsOwnString(t *testing.T) {
	path := tempConfig(t, "[net]\n")
	err := SaveJob(path, Job{
		Name: "evil", Schedule: "@hourly", Enabled: true,
		Script: "echo hi\n'''\n[[client]]\nip = \"1.2.3.4\"\n",
	})
	if err == nil {
		t.Fatal("a script containing ''' was accepted")
	}
}

// A managed job must not shadow a hand-written one with the same name: two
// [[job]] entries with one name render two cron lines.
func TestSaveJobRefusesToShadowAHandWrittenJob(t *testing.T) {
	path := tempConfig(t, withHandWrittenJob)
	err := SaveJob(path, Job{Name: "handmade", Schedule: "@weekly", Script: "true\n", Enabled: true})
	if err == nil {
		t.Fatal("a managed job shadowed a hand-written one with the same name")
	}
	if !strings.Contains(err.Error(), "hand-written") {
		t.Errorf("the error does not explain the clash: %v", err)
	}
}

func TestToggleAndRemoveJob(t *testing.T) {
	path := tempConfig(t, "[net]\n")
	if err := SaveJob(path, Job{Name: "backup", Schedule: "@daily", Script: "true\n", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := ToggleJob(path, "backup", false); err != nil {
		t.Fatal(err)
	}
	jobs, _ := Jobs(path)
	if jobs[0].Enabled {
		t.Error("the job is still enabled after being disabled")
	}
	if err := RemoveJob(path, "backup"); err != nil {
		t.Fatal(err)
	}
	if jobs, _ = Jobs(path); len(jobs) != 0 {
		t.Errorf("the job survived removal: %+v", jobs)
	}
	if err := RemoveJob(path, "backup"); err == nil {
		t.Error("removing an absent job reported success")
	}
}

// A hand-written job is listed because it still runs, but this tool must refuse
// to delete something it did not write.
func TestRemoveRefusesHandWrittenJobs(t *testing.T) {
	path := tempConfig(t, withHandWrittenJob)
	err := RemoveJob(path, "handmade")
	if err == nil || !strings.Contains(err.Error(), "hand-written") {
		t.Fatalf("expected a refusal naming the hand-written job, got %v", err)
	}
}
