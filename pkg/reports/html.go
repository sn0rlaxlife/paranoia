// Package reports provides functionality to generate HTML reports.
package reports

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// Add check on validation
func validateEmbeddedTemplates() error {
	entries, err := templatesFS.ReadDir("templates")
	if err != nil {
		return fmt.Errorf("failed to read embedded templates root: %w", err)
	}

	if len(entries) == 0 {
		return fmt.Errorf("no embedded templates found (go:embed likely misconfigured)")
	}

	found := false
	for _, e := range entries {
		if !e.IsDir() && e.Name() == "index.html" {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("index.html not found in embedded templates")
	}

	return nil
}

//go:embed templates/index.html
var templatesFS embed.FS

type Finding struct {
	Raw      string
	Severity string // e.g. "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
	BadgeCls string // CSS class for badge
}

type HTMLView struct {
	Title       string
	GeneratedAt string
	Counts      map[string]int
	Total       int
	Findings    []Finding
}

// ParseSeverity tries to infer severity from strings like: "[HIGH] ..."
// Falls back to INFO.
func ParseSeverity(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "[") {
		if end := strings.Index(s, "]"); end > 1 {
			sev := strings.ToUpper(strings.TrimSpace(s[1:end]))
			switch sev {
			case "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO":
				return sev
			}
		}
	}
	// If you sometimes use "Vulnerability:" lines, treat as HIGH by default (tweak if you want)
	if strings.HasPrefix(strings.ToLower(s), "vulnerability:") {
		return "HIGH"
	}
	return "INFO"
}

func badgeClass(sev string) string {
	switch sev {
	case "CRITICAL":
		return "badge critical"
	case "HIGH":
		return "badge high"
	case "MEDIUM":
		return "badge medium"
	case "LOW":
		return "badge low"
	default:
		return "badge info"
	}
}

// Add helper for new views
func BuildReportView(title string, rawFindings []string) ReportView {
	hv := buildView(title, rawFindings)
	return ReportView{
		Title:       hv.Title,
		GeneratedAt: hv.GeneratedAt,
		Counts:      hv.Counts,
		Total:       hv.Total,
		Findings:    hv.Findings,
	}
}

// Helper to convert raw findings
// Helper to convert raw finding strings to Finding structs
func CategorizeFindings(rawFindings []string) []Finding {
	out := make([]Finding, 0, len(rawFindings))
	for _, f := range rawFindings {
		sev := ParseSeverity(f)
		out = append(out, Finding{
			Raw:      f,
			Severity: sev,
			BadgeCls: badgeClass(sev),
		})
	}
	return out
}

func buildView(title string, findings []string) HTMLView {
	counts := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
		"INFO":     0,
	}

	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		sev := ParseSeverity(f)
		counts[sev]++
		out = append(out, Finding{
			Raw:      f,
			Severity: sev,
			BadgeCls: badgeClass(sev),
		})
	}

	// Nice default ordering: CRITICAL -> HIGH -> MEDIUM -> LOW -> INFO
	rank := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
	sort.SliceStable(out, func(i, j int) bool {
		ri := rank[out[i].Severity]
		rj := rank[out[j].Severity]
		if ri != rj {
			return ri < rj
		}
		return out[i].Raw < out[j].Raw
	})

	total := 0
	for _, v := range counts {
		total += v
	}

	return HTMLView{
		Title:       title,
		GeneratedAt: time.Now().Format(time.RFC1123),
		Counts:      counts,
		Total:       total,
		Findings:    out,
	}
}

func GenerateHTMLReport(title string, findings []string, outputPath string) error {
	tplBytes, err := templatesFS.ReadFile("templates/index.html")
	if err != nil {
		return fmt.Errorf("read template: %w", err)
	}

	tpl, err := template.New("report").Funcs(template.FuncMap{
		// Percent helper used for the donut chart + progress bars.
		"pct": func(part, total int) int {
			if total <= 0 {
				return 0
			}
			return int(float64(part) / float64(total) * 100.0)
		},
	}).Parse(string(tplBytes))
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create report file: %w", err)
	}
	defer f.Close()

	view := buildView(title, findings)
	if err := tpl.Execute(f, view); err != nil {
		return fmt.Errorf("render template: %w", err)
	}
	return nil
}

func GenerateHTMLReportView(view ReportView, outputPath string) error {
	tplBytes, err := templatesFS.ReadFile("templates/index.html")
	if err != nil {
		return fmt.Errorf("read template: %w", err)
	}

	tpl, err := template.New("report").Funcs(template.FuncMap{
		"pct": func(part, total int) int {
			if total <= 0 {
				return 0
			}
			return int(float64(part) / float64(total) * 100.0)
		},
		"lower": strings.ToLower,
	}).Parse(string(tplBytes))
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create report file: %w", err)
	}
	defer f.Close()

	if err := tpl.Execute(f, view); err != nil {
		return fmt.Errorf("render template: %w", err)
	}
	return nil
}

func ServeHTMLReport(title string, findings []string, outputPath string, port string) error {
	if err := validateEmbeddedTemplates(); err != nil {
		return err
	}

	if err := GenerateHTMLReport(title, findings, outputPath); err != nil {
		return fmt.Errorf("failed to generate HTML report: %w", err)
	}

	// Serve the generated HTML file
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, outputPath)
	})

	fmt.Printf("Serving HTML report at http://localhost:%s\n", port)
	return http.ListenAndServe(":"+port, mux)
}

func ServeHTMLReportView(view ReportView, outputPath string, port string) error {
	if err := validateEmbeddedTemplates(); err != nil {
		return err
	}

	if err := GenerateHTMLReportView(view, outputPath); err != nil {
		return fmt.Errorf("failed to generate HTML report: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, outputPath)
	})

	fmt.Printf("Serving HTML report at http://localhost:%s\n", port)
	return http.ListenAndServe(":"+port, mux)
}
