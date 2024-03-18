package cmd

import (
	"context"
	"fmt"
	"kspm/pkg/controlchecks"
	"os"

	"github.com/spf13/cobra"
)

var namespace string

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate a report",
	Long:  `This command generates a report of the cluster's security posture.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Initialize Kubernetes client
		cfg, err := trivyK8s.InitClient()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error initializing Kubernetes client: %v\n", err)
			os.Exit(1)
		}
		// Fetch and format vulnerabilities
		vulnerabilities, err := pkg.reports.FetchAndFormatVulnerabilities(context.Background(), cfg, namespace)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching vulnerabilities: %v\n", err)
			os.Exit(1)
		}
		// Print the vulnerabilities table
		pkg.reports.PrintVulnerabilityTable(vulnerabilities)

		controlchecks.FetchVulnerabilityReports(context.Background(), cfg, namespace)
	},
}

func init() {
	reportCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "The namespace to generate the report for")
	rootCmd.AddCommand(reportCmd)
}
