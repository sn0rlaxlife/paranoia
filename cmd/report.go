package cmd

import (
	"context"
	"fmt"
	"kspm/pkg/controlchecks"
	"os"

	"kspm/pkg/reports"

	"github.com/spf13/cobra"
	"k8s.io/client-go/rest"
)

var namespace string

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate a report",
	Long:  `This command generates a report of the cluster's security posture.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Initialize Kubernetes client
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			fmt.Fprintln(os.Stderr, "Error: KUBECONFIG environment variable not set")
			os.Exit(1)
		}
		// Fetch and format vulnerabilities
		vulnerabilities, err := reports.FetchAndFormatVulnerabilities(context.Background(), kubeconfig, namespace)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching vulnerabilities: %v\n", err)
			os.Exit(1)
		}
		// Print the vulnerabilities table
		reports.PrintVulnerabilityTable(vulnerabilities)
		// Fetch and print RBAC settings
		// Initialize a clientset that is taken by the Fetch Vulnerability Reports function
		cfg, err := rest.InClusterConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating in-cluster config: %v\n", err)
			os.Exit(1)
		}
		controlchecks.FetchVulnerabilityReports(context.Background(), cfg, namespace)
	},
}

func init() {
	reportCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "The namespace to generate the report for")
	rootCmd.AddCommand(reportCmd)
}
