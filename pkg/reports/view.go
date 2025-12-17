package reports

import "kspm/pkg/riskposture"

type ReportView struct {
	// Top-level report fields - Legacy
	Title       string
	GeneratedAt string
	Counts      map[string]int
	Total       int
	Findings    []Finding

	// New: Fields for detailed posture report
	RBACFindings         []Finding
	DeploymentFindings   []Finding
	ControlPlaneFindings []Finding
	PodFindings          []Finding
	SecretFindings       []Finding

	// New posture fields
	RiskScore   int
	RiskCounts  riskposture.RiskLevelCounts
	RiskDrivers []string

	AttackPaths  []riskposture.AttackPath
	Remediations []riskposture.Remediation
}
