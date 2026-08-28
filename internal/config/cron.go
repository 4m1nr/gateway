package config

import (
	"regexp"
	"sort"
	"strings"
)

// cronShorthand are the @-forms cron accepts in place of five fields.
var cronShorthand = map[string]bool{
	"@yearly": true, "@annually": true, "@monthly": true, "@weekly": true,
	"@daily": true, "@midnight": true, "@hourly": true, "@reboot": true,
}

// cronField is deliberately permissive within each field (ranges, steps, lists,
// names) but strict about the shape: a five-field line, or a known @shorthand.
// A malformed entry in /etc/cron.d is not rejected by cron, it is silently
// ignored — so the job would simply never run and nothing would say why.
var cronField = regexp.MustCompile(`^[0-9A-Za-z*/,\-]+$`)

func validateCron(expr, where string) error {
	if expr == "" {
		return errf("%s.schedule is empty. Use five cron fields "+
			`("0 4 * * *") or a shorthand like "@daily".`, where)
	}
	if strings.HasPrefix(expr, "@") {
		if !cronShorthand[expr] {
			return errf("%s.schedule %q is not a known shorthand. Expected one of: %s",
				where, expr, strings.Join(sortedShorthands(), ", "))
		}
		return nil
	}
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return errf("%s.schedule %q has %d field(s); cron needs 5 "+
			"(minute hour day-of-month month day-of-week)", where, expr, len(fields))
	}
	for pos, field := range fields {
		if !cronField.MatchString(field) {
			return errf("%s.schedule field %d (%q) contains "+
				"characters cron will not accept", where, pos+1, field)
		}
	}
	// cron treats % in a crontab line as a newline and silently truncates
	// there, so a `curl -w '%{time_total}'` schedule becomes a different
	// command with no error.
	if strings.Contains(expr, "%") {
		return errf("%s.schedule contains '%%', which cron treats as a newline", where)
	}
	return nil
}

func sortedShorthands() []string {
	out := make([]string, 0, len(cronShorthand))
	for k := range cronShorthand {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
