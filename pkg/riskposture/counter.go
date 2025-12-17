package riskposture

import (
	"fmt"
	"math"
	"sort"
)

type Signal struct {
	Name     string // e.g. Privileged Pod, Cluster Admin Binding
	Severity string // e.g. "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
	Weight   int    // numeric contribution used
}

// Risk level counts
type RiskLevelCounts struct {
	Critical int
	High     int
	Medium   int
	Low      int
}

// Method to enumerate
func (rp *RiskPosture) CountRiskLevels() RiskLevelCounts {
	var c RiskLevelCounts
	for _, s := range rp.Signals {
		switch s.Severity {
		case "CRITICAL":
			c.Critical++
		case "HIGH":
			c.High++
		case "MEDIUM":
			c.Medium++
		case "LOW":
			c.Low++
		}
	}
	return c
}

// RiskPosture is a struct that represents a risk posture.
type RiskPosture struct {
	// Functions is the list of functions.
	Signals []Signal
}

// Add Attack Paths
type AttackPath struct {
	ID         string
	Title      string
	Severity   string
	Confidence int
	Steps      []AttackStep
	Evidence   []string
}

type AttackStep struct {
	Kind      string
	Namespace string
	Name      string
	Why       string
}

// Add remediation structs
type Remediation struct {
	ID        string
	Title     string
	Priority  string
	AppliesTo string
	YAML      string
}

func (rp *RiskPosture) Remediations() []Remediation {
	var fixes []Remediation

	for _, s := range rp.Signals {
		if s.Name == "NoNetworkPolicy" {
			fixes = append(fixes, Remediation{
				ID:        "default-deny-netpol",
				Title:     "Apply default deny NetworkPolicy",
				Priority:  "HIGH",
				AppliesTo: "Namespace",
				YAML: `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: {{NAMESPACE}}
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
`,
			})
		}
	}

	return fixes
}

// ---- Add method for this
func (rp *RiskPosture) DeriveAttackPaths() []AttackPath {
	// Declare var paths for collection
	var paths []AttackPath

	// heuristic example
	hasClusterAdmin := false
	hasWorkload := false

	for _, s := range rp.Signals {
		if s.Name == "ClusterAdminBinding" {
			hasClusterAdmin = true
		}
		if s.Name == "PrivilegedPod" {
			hasWorkload = true
		}
	}

	// Add if statements on these
	if hasClusterAdmin && hasWorkload {
		paths = append(paths, AttackPath{
			ID:         "pod-to-cluster-admin",
			Title:      "Workload to Cluster Admin Escalation",
			Severity:   "CRITICAL",
			Confidence: 85,
			Steps: []AttackStep{
				{Kind: "Pod", Why: "Privileged workload detected"},
				{Kind: "RBAC", Why: "cluster-admin role bound"},
			},
			Evidence: []string{
				"PrivilegedPod",
				"ClusterAdminBinding",
			},
		})
	}

	return paths
}

// NewRiskPosture creates a new RiskPosture with the given functions.
func NewRiskPosture(signals []Signal) *RiskPosture {
	return &RiskPosture{
		Signals: signals,
	}
}

// CountRiskLevels counts the number of functions that meet each risk level.
func (rp *RiskPosture) Score() (int, []string) {
	// Take the MAX weight per signal name (prevents saturating on repeats)
	maxByName := map[string]int{}
	sevByName := map[string]string{}

	for _, s := range rp.Signals {
		if s.Weight > maxByName[s.Name] {
			maxByName[s.Name] = s.Weight
			sevByName[s.Name] = s.Severity
		}
	}

	// Use sqrt scaling to prevent saturation
	// Score = sqrt(sum of squared weights) * multiplier
	var sumSquared float64
	for _, w := range maxByName {
		sumSquared += float64(w * w)
	}

	score := int(math.Sqrt(sumSquared) * 1.5)
	if score > 100 {
		score = 100
	}

	// Alternative: Cap based on unique signal types
	// score := len(maxByName) * 8  // 12-13 unique issues = 100 score
	// if score > 100 { score = 100 }

	// drivers sorted by weight desc
	type pair struct {
		name string
		w    int
		sev  string
	}
	arr := make([]pair, 0, len(maxByName))
	for n, w := range maxByName {
		arr = append(arr, pair{name: n, w: w, sev: sevByName[n]})
	}
	sort.Slice(arr, func(i, j int) bool { return arr[i].w > arr[j].w })

	var drivers []string
	for i := 0; i < len(arr) && i < 5; i++ {
		drivers = append(drivers, fmt.Sprintf("%s (%s, +%d)", arr[i].name, arr[i].sev, arr[i].w))
	}
	if len(drivers) == 0 {
		drivers = []string{"No high-risk signals detected"}
	}
	return score, drivers
}
