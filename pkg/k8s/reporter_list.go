package k8s

import (
	"fmt"

	"github.com/fatih/color"
)

// Declare type
type Reporter struct {
	Findings []string
	Quiet    bool
}

func NewReporter(quiet bool) *Reporter {
	return &Reporter{
		Findings: []string{},
		Quiet:    quiet,
	}
}

func (r *Reporter) Emit(sev, cat, ns, kind, name, msg string) {
	// 1) Append structured finding
	r.Findings = append(r.Findings,
		fmt.Sprintf(
			"[SEV=%s] [CAT=%s] ns=%s kind=%s name=%s msg=%q",
			sev, cat, ns, kind, name, msg,
		),
	)

	// 2) Optional console output
	if r.Quiet {
		return
	}

	switch sev {
	case "CRITICAL":
		color.New(color.FgHiRed).Printf("[CRITICAL] %s/%s (%s): %s\n", kind, name, ns, msg)
	case "HIGH":
		color.New(color.FgRed).Printf("[HIGH] %s/%s (%s): %s\n", kind, name, ns, msg)
	case "MED":
		color.New(color.FgYellow).Printf("[MED] %s/%s (%s): %s\n", kind, name, ns, msg)
	default:
		color.New(color.FgCyan).Printf("[INFO] %s/%s (%s): %s\n", kind, name, ns, msg)
	}
}
