package riskposture

import "strings"

// SignalsFromFindings converts your string findings into risk signals.
// v1: severity-driven (fast). v2: add more parsing (resource type, namespace, etc).
func SignalsFromFindings(findings []string) []Signal {
	var out []Signal
	seen := map[string]bool{} // dedupe by Name

	for _, f := range findings {
		sev := ParseSeverityFromFinding(f)
		l := strings.ToLower(f)

		add := func(name, severity string, weight int) {
			// de-dupe by category; score uses max per name anyway
			if seen[name] {
				return
			}
			seen[name] = true
			out = append(out, Signal{Name: name, Severity: severity, Weight: weight})
		}

		// RBAC / cluster-admin
		if strings.Contains(l, "cluster-admin") {
			add("ClusterAdminBinding", "CRITICAL", 40)
			continue
		}

		// NetworkPolicy
		if strings.Contains(l, "networkpolicy") || strings.Contains(l, "no networkpolicy") {
			add("NoNetworkPolicy", "HIGH", 20)
			continue
		}

		// Privileged / host namespaces
		if strings.Contains(l, "privileged") || strings.Contains(l, "hostnetwork") || strings.Contains(l, "hostpid") {
			add("PrivilegedWorkload", "HIGH", 25)
			continue
		}

		// Secrets exposure
		if strings.Contains(l, "secret") && (strings.Contains(l, "env") || strings.Contains(l, "mount")) {
			add("SecretsExposure", "HIGH", 20)
			continue
		}

		// Fallback: severity-only category (still not “Finding”)
		switch sev {
		case "CRITICAL":
			add("CriticalFindingsPresent", "CRITICAL", 20)
		case "HIGH":
			add("HighFindingsPresent", "HIGH", 10)
		case "MEDIUM":
			add("MediumFindingsPresent", "MEDIUM", 5)
		}
	}

	return out
}

func ParseSeverityFromFinding(s string) string {
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
	if strings.HasPrefix(strings.ToLower(s), "vulnerability:") {
		return "HIGH"
	}
	return "INFO"
}

// Weight for Severity
func weightForSeverity(sev string) int {
	switch sev {
	case "CRITICAL":
		return 20
	case "HIGH":
		return 10
	case "MEDIUM":
		return 5
	case "LOW":
		return 2
	default:
		return 0
	}
}
