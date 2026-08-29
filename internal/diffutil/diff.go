// Package diffutil produces unified diffs between two texts.
//
// `gw diff` is the last thing you read before `gw apply` rewrites the firewall
// on a box the whole house routes through, so it has to be exact and it has to
// be legible. The dashboard renders the same data, which is why this returns
// structured hunks rather than a formatted string.
package diffutil

import (
	"fmt"
	"strings"
)

// Op is what happened to a line.
type Op int

const (
	Equal Op = iota
	Insert
	Delete
)

// Line is one line of a diff.
type Line struct {
	Op   Op
	Text string
	// OldLine and NewLine are 1-based positions, or 0 where the line does not
	// exist on that side.
	OldLine int
	NewLine int
}

// Hunk is a run of changed lines plus its surrounding context.
type Hunk struct {
	OldStart, OldCount int
	NewStart, NewCount int
	Lines              []Line
}

// Header renders the @@ line.
func (h Hunk) Header() string {
	return fmt.Sprintf("@@ -%d,%d +%d,%d @@", h.OldStart, h.OldCount, h.NewStart, h.NewCount)
}

// Unified compares two texts and returns the changed hunks, with `context`
// lines of surrounding context. No hunks means the texts are identical.
func Unified(oldText, newText string, context int) []Hunk {
	if oldText == newText {
		return nil
	}
	if context < 0 {
		context = 0
	}
	a, b := splitLines(oldText), splitLines(newText)
	return hunks(diffLines(a, b), context)
}

// splitLines keeps the text's line structure without inventing a trailing empty
// line for a file that ends in a newline, which every generated file does.
func splitLines(text string) []string {
	if text == "" {
		return nil
	}
	lines := strings.Split(text, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// diffLines walks the LCS table to produce a line-by-line edit script.
func diffLines(a, b []string) []Line {
	// Trim the common prefix and suffix first. Generated files usually differ
	// in a handful of lines, so this keeps the quadratic table small.
	start := 0
	for start < len(a) && start < len(b) && a[start] == b[start] {
		start++
	}
	endA, endB := len(a), len(b)
	for endA > start && endB > start && a[endA-1] == b[endB-1] {
		endA--
		endB--
	}

	var out []Line
	for i := 0; i < start; i++ {
		out = append(out, Line{Op: Equal, Text: a[i], OldLine: i + 1, NewLine: i + 1})
	}
	out = append(out, lcsScript(a[start:endA], b[start:endB], start)...)
	for i := endA; i < len(a); i++ {
		out = append(out, Line{
			Op: Equal, Text: a[i],
			OldLine: i + 1, NewLine: i - endA + endB + 1,
		})
	}
	return out
}

// lcsScript diffs the middle section, with offset added to line numbers.
func lcsScript(a, b []string, offset int) []Line {
	n, m := len(a), len(b)
	if n == 0 && m == 0 {
		return nil
	}
	// table[i][j] is the LCS length of a[i:] and b[j:].
	table := make([][]int, n+1)
	for i := range table {
		table[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				table[i][j] = table[i+1][j+1] + 1
			} else if table[i+1][j] >= table[i][j+1] {
				table[i][j] = table[i+1][j]
			} else {
				table[i][j] = table[i][j+1]
			}
		}
	}

	var out []Line
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			out = append(out, Line{Op: Equal, Text: a[i],
				OldLine: offset + i + 1, NewLine: offset + j + 1})
			i++
			j++
		case table[i+1][j] >= table[i][j+1]:
			out = append(out, Line{Op: Delete, Text: a[i], OldLine: offset + i + 1})
			i++
		default:
			out = append(out, Line{Op: Insert, Text: b[j], NewLine: offset + j + 1})
			j++
		}
	}
	for ; i < n; i++ {
		out = append(out, Line{Op: Delete, Text: a[i], OldLine: offset + i + 1})
	}
	for ; j < m; j++ {
		out = append(out, Line{Op: Insert, Text: b[j], NewLine: offset + j + 1})
	}
	return out
}

// hunks groups the edit script into runs of change plus context.
func hunks(script []Line, context int) []Hunk {
	var out []Hunk
	i := 0
	for i < len(script) {
		if script[i].Op == Equal {
			i++
			continue
		}
		// Walk back over the leading context.
		start := i - context
		if start < 0 {
			start = 0
		}
		// Extend while changes keep appearing within 2*context of each other,
		// so nearby edits share one hunk instead of repeating context between
		// them.
		end := i
		for end < len(script) {
			if script[end].Op != Equal {
				end++
				continue
			}
			run := 0
			for end+run < len(script) && script[end+run].Op == Equal {
				run++
			}
			if run > context*2 || end+run >= len(script) {
				break
			}
			end += run
		}
		stop := end + context
		if stop > len(script) {
			stop = len(script)
		}

		h := Hunk{Lines: script[start:stop]}
		for _, l := range h.Lines {
			if l.Op != Insert {
				if h.OldStart == 0 {
					h.OldStart = l.OldLine
				}
				h.OldCount++
			}
			if l.Op != Delete {
				if h.NewStart == 0 {
					h.NewStart = l.NewLine
				}
				h.NewCount++
			}
		}
		out = append(out, h)
		i = stop
	}
	return out
}

// Format renders hunks the way `diff -u` would, without the ---/+++ header.
func Format(hs []Hunk) string {
	var b strings.Builder
	for _, h := range hs {
		b.WriteString(h.Header())
		b.WriteByte('\n')
		for _, l := range h.Lines {
			switch l.Op {
			case Insert:
				b.WriteByte('+')
			case Delete:
				b.WriteByte('-')
			default:
				b.WriteByte(' ')
			}
			b.WriteString(l.Text)
			b.WriteByte('\n')
		}
	}
	return b.String()
}
