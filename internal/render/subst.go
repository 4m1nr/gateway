package render

import (
	"fmt"
	"strings"

	gateway "github.com/am1nr/gateway"
)

// templateFile reads an embedded template.
func templateFile(rel string) (string, error) {
	data, err := gateway.Templates.ReadFile("templates/" + rel)
	if err != nil {
		return "", fmt.Errorf("embedded template %s: %w", rel, err)
	}
	return string(data), nil
}

// subst replaces {{KEY}} placeholders and refuses to return text that still
// contains one.
//
// An unsubstituted placeholder in a live nftables ruleset is not a cosmetic
// problem: nft rejects the file, gw-network fails to load it, and the box comes
// up with no firewall at all. Failing here, before anything is written, is the
// only safe place to notice.
func subst(text string, mapping map[string]string) (string, error) {
	for key, val := range mapping {
		text = strings.ReplaceAll(text, "{{"+key+"}}", val)
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "{{") && strings.Contains(line, "}}") {
			return "", fmt.Errorf("unsubstituted placeholder: %s", strings.TrimSpace(line))
		}
	}
	return text, nil
}

// nftElements renders a set's elements, or nothing at all for an empty set —
// nft rejects `elements = { }`.
func nftElements(items []string, indent int) string {
	if len(items) == 0 {
		return ""
	}
	pad := strings.Repeat(" ", indent)
	return fmt.Sprintf("%selements = { %s }\n", pad, strings.Join(items, ", "))
}
