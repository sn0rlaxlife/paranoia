package trivytypes // Or the appropriate package name
import (
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

// Vulnerability struct (mirroring the Trivy Operator's definition)
type Vulnerability struct {
	// VulnerabilityID the vulnerability identifier.
	VulnerabilityID string `json:"vulnerabilityID"`

	// Resource is a vulnerable package, application, or library.
	Resource string `json:"resource"`

	// InstalledVersion indicates the installed version of the Resource.
	InstalledVersion string `json:"installedVersion"`

	// FixedVersion indicates the version of the Resource in which this vulnerability has been fixed.
	FixedVersion string `json:"fixedVersion"`
	// PublishedDate indicates the date of published CVE.
	PublishedDate string `json:"publishedDate"`
	// LastModifiedDate indicates the last date CVE has been modified.
	LastModifiedDate string `json:"lastModifiedDate"`
	// Severity level of a vulnerability or a configuration audit check.
	Severity    v1alpha1.Severity `json:"severity"` // Notice: Declared as 'Severity'
	Title       string            `json:"title"`
	Description string            `json:"description,omitempty"`
	CVSSSource  string            `json:"cvsssource,omitempty"`
	PrimaryLink string            `json:"primaryLink,omitempty"`
	// +optional
	Links []string `json:"links"`
	Score *float64 `json:"score,omitempty"`
	// +optional
	Target string `json:"target"`
	// +optional
	CVSS types.VendorCVSS `json:"cvss,omitempty"`
	// +optional
	Class       string `json:"class,omitempty"`
	PackageType string `json:"packageType,omitempty"`
	PkgPath     string `json:"packagePath,omitempty"`
}

// Custom Severity type
type Severity string

// Severity Constants (matching Trivy Operator)
const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityUnknown  Severity = "UNKNOWN"
)

// convertSecurity converts v1alpha.Severity to trivytypes.Severity
func ConvertSecurity(s v1alpha1.Severity) Severity {
	switch s {
	case v1alpha1.SeverityCritical:
		return SeverityCritical
	case v1alpha1.SeverityHigh:
		return SeverityHigh
	case v1alpha1.SeverityMedium:
		return SeverityMedium
	case v1alpha1.SeverityLow:
		return SeverityLow
	default:
		return SeverityUnknown
	}
}
