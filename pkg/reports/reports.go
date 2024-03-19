package reports

import (
	"context"
	"fmt"
	"kspm/pkg/controlchecks"
	"kspm/pkg/trivytypes"
	"os"
	"strings"

	"github.com/fatih/color"
	"k8s.io/client-go/tools/clientcmd"
)

func FetchAndFormatVulnerabilities(ctx context.Context, kuberconfig string, namespace string) ([]trivytypes.Vulnerability, error) {
	// Use the kubeconfig file to create a config
	kubeconfig := os.Getenv("KUBECONFIG")
	fmt.Printf("KUBECONFIG: %s\n", kubeconfig)
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to build config: %w", err)
	}
	reportList, err := controlchecks.FetchVulnerabilityReports(ctx, cfg, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch vulnerability reports: %w", err)
	}
	// Process vulnerabilities into a slice of 'Vulnerability' structs
	var formattedVulnerabilities []trivytypes.Vulnerability // Use the Vulnerability type from the trivytypes package
	for _, trivyReport := range reportList {
		for _, trivyVuln := range trivyReport.Report.Vulnerabilities {
			reportVuln := trivytypes.Vulnerability{
				VulnerabilityID: trivyVuln.VulnerabilityID,
				Description:     trivyVuln.Description,
			}
			formattedVulnerabilities = append(formattedVulnerabilities, reportVuln)
		}
	}

	return formattedVulnerabilities, nil
}

func PrintVulnerabilityTable(vulnerabilities []trivytypes.Vulnerability) {
	// Header formatting
	headerFormat := "%-30s %-20s %-15s %-10s %s\n"
	header := fmt.Sprintf(headerFormat,
		color.HiBlueString("CVE-ID"),
		color.HiBlueString("Package"),
		color.HiBlueString("Version"),
		color.HiBlueString("Severity"),
		color.HiBlueString("Description"))

	fmt.Println(header)                           // Print the header line
	fmt.Println(strings.Repeat("-", len(header))) // Separator

	// Row formatting with highlighted severity
	rowFormat := "%-30s %-20s %-15s %-10s %s\n"
	for _, vuln := range vulnerabilities {
		severityColor := color.New(color.FgWhite) // Default color
		if vuln.Severity == "HIGH" {
			severityColor = color.New(color.FgRed, color.Bold)
		}
		// Colorize the fields
		vulnIDColor := color.New(color.FgGreen).SprintFunc()
		packageColor := color.New(color.FgYellow).SprintFunc()
		descriptionColor := color.New(color.FgCyan).SprintFunc()

		fmt.Printf(rowFormat, vulnIDColor(vuln.VulnerabilityID), packageColor(fmt.Sprintf("%+v", vuln.CVSS)), vuln.CVSSSource, severityColor.Sprint(vuln.Title), descriptionColor(vuln.Description)) // Print each vulnerability row
	}
}
