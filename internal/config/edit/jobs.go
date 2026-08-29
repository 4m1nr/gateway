package edit

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

// The managed region. Jobs this tool writes live between these markers and the
// whole region is regenerated on every change.
//
// Textual surgery on a multi-line script block is how you end up with a
// half-deleted heredoc in your config; regenerating a machine-managed region is
// boring and safe, and it leaves hand-written jobs elsewhere in the file alone.
const (
	jobsBegin = "# >>> gw job entries — managed by `gw job` and the dashboard >>>"
	jobsEnd   = "# <<< gw job entries <<<"
)

var jobNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,23}$`)

// Job is a bash script on a cron schedule.
type Job struct {
	Name        string `json:"name"`
	Schedule    string `json:"schedule"`
	Script      string `json:"script"`
	User        string `json:"user"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description"`
	// Managed reports whether this job lives in the region this tool rewrites.
	// A hand-written job still runs, so it is listed, but it is not touched.
	Managed bool `json:"managed"`
}

// Jobs returns every [[job]] in the file, marking which are managed.
func Jobs(path string) ([]Job, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	all, err := decodeJobs(string(raw))
	if err != nil {
		return nil, err
	}
	managed := map[string]bool{}
	if region, ok := managedRegion(string(raw)); ok {
		inner, err := decodeJobs(region)
		if err == nil {
			for _, j := range inner {
				managed[j.Name] = true
			}
		}
	}
	for i := range all {
		all[i].Managed = managed[all[i].Name]
	}
	return all, nil
}

func decodeJobs(text string) ([]Job, error) {
	var doc struct {
		Job []struct {
			Name        string `toml:"name"`
			Schedule    string `toml:"schedule"`
			Script      string `toml:"script"`
			User        string `toml:"user"`
			Enabled     *bool  `toml:"enabled"`
			Description string `toml:"description"`
		} `toml:"job"`
	}
	if _, err := toml.Decode(text, &doc); err != nil {
		return nil, err
	}
	out := make([]Job, 0, len(doc.Job))
	for _, j := range doc.Job {
		enabled := true
		if j.Enabled != nil {
			enabled = *j.Enabled
		}
		user := j.User
		if user == "" {
			user = "root"
		}
		out = append(out, Job{
			Name: j.Name, Schedule: j.Schedule, Script: j.Script,
			User: user, Enabled: enabled, Description: j.Description,
		})
	}
	return out, nil
}

// managedRegion returns the region's contents with the markers stripped.
func managedRegion(text string) (string, bool) {
	a := strings.Index(text, jobsBegin)
	b := strings.Index(text, jobsEnd)
	if a < 0 || b < 0 || b < a {
		return "", false
	}
	return text[a+len(jobsBegin) : b], true
}

// managedJobs returns only the jobs inside the region.
func managedJobs(text string) []Job {
	region, ok := managedRegion(text)
	if !ok {
		return nil
	}
	jobs, err := decodeJobs(region)
	if err != nil {
		return nil
	}
	return jobs
}

// SaveJob adds or replaces a managed job.
func SaveJob(path string, job Job) error {
	if !jobNameRE.MatchString(job.Name) {
		return fmt.Errorf("job name must be 1-24 chars of lowercase letters, digits or dashes")
	}
	if strings.TrimSpace(job.Script) == "" {
		return fmt.Errorf("the script is empty — nothing to run")
	}
	if job.User == "" {
		job.User = "root"
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	text := string(raw)

	// A hand-written job with the same name must not be shadowed: two [[job]]
	// entries with one name render two cron lines, and which one wins is not
	// something the config makes visible.
	managed := managedJobs(text)
	inRegion := false
	for _, j := range managed {
		if j.Name == job.Name {
			inRegion = true
			break
		}
	}
	if !inRegion {
		all, err := decodeJobs(text)
		if err != nil {
			return err
		}
		for _, j := range all {
			if j.Name == job.Name {
				return fmt.Errorf("a hand-written job named %q already exists in %s. "+
					"Rename one of them, or edit that entry directly", job.Name, path)
			}
		}
	}

	out := make([]Job, 0, len(managed)+1)
	replaced := false
	for _, j := range managed {
		if j.Name == job.Name {
			out = append(out, job)
			replaced = true
			continue
		}
		out = append(out, j)
	}
	if !replaced {
		out = append(out, job)
	}
	return writeJobs(path, text, out)
}

// RemoveJob deletes a managed job.
func RemoveJob(path, name string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	text := string(raw)

	managed := managedJobs(text)
	out := make([]Job, 0, len(managed))
	found := false
	for _, j := range managed {
		if j.Name == name {
			found = true
			continue
		}
		out = append(out, j)
	}
	if !found {
		all, err := decodeJobs(text)
		if err == nil {
			for _, j := range all {
				if j.Name == name {
					return fmt.Errorf("%q is a hand-written job — remove it from %s yourself", name, path)
				}
			}
		}
		return fmt.Errorf("no job named %q", name)
	}
	return writeJobs(path, text, out)
}

// ToggleJob enables or disables a managed job.
func ToggleJob(path, name string, enabled bool) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	text := string(raw)
	managed := managedJobs(text)
	for i := range managed {
		if managed[i].Name == name {
			managed[i].Enabled = enabled
			return writeJobs(path, text, managed)
		}
	}
	return fmt.Errorf("no managed job named %q", name)
}

// writeJobs regenerates the managed region.
func writeJobs(path, text string, jobs []Job) error {
	bodies := make([]string, 0, len(jobs))
	for _, j := range jobs {
		body, err := serialiseJob(j)
		if err != nil {
			return err
		}
		bodies = append(bodies, body)
	}

	block := jobsBegin + "\n" + jobsEnd + "\n"
	if len(bodies) > 0 {
		block = jobsBegin + "\n" + strings.Join(bodies, "\n\n") + "\n" + jobsEnd + "\n"
	}

	a := strings.Index(text, jobsBegin)
	b := strings.Index(text, jobsEnd)
	if a >= 0 && b >= a {
		text = text[:a] + strings.TrimRight(block, "\n") + text[b+len(jobsEnd):]
	} else {
		text = strings.TrimRight(text, "\n") + "\n\n" + block
	}
	return writeFile(path, text)
}

// serialiseJob writes one [[job]] table.
//
// The script is a TOML *literal* multi-line string, the single-quoted kind. The
// double-quoted kind processes escapes, so a bash line continuation would be
// collapsed and a backslash-n would become a real newline — quietly rewriting
// the script between what you wrote and what actually runs.
func serialiseJob(j Job) (string, error) {
	script := strings.TrimRight(j.Script, "\n")
	if strings.Contains(script, "'''") {
		return "", fmt.Errorf("job %s: the script contains ''' , which terminates a "+
			"TOML literal string. Remove it or edit gateway.toml by hand", j.Name)
	}
	lines := []string{
		"[[job]]",
		fmt.Sprintf("name        = %q", j.Name),
		fmt.Sprintf("schedule    = %q", j.Schedule),
		fmt.Sprintf("user        = %q", j.User),
		fmt.Sprintf("enabled     = %t", j.Enabled),
	}
	if j.Description != "" {
		lines = append(lines, fmt.Sprintf("description = %q",
			strings.ReplaceAll(j.Description, `"`, "'")))
	}
	lines = append(lines, "script      = '''", script, "'''")
	return strings.Join(lines, "\n"), nil
}
