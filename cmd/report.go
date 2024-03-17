package cmd

import (
	"context"
	"kspm/pkg/controlchecks"
	"kspm/pkg/k8s"

	"github.com/spf13/cobra"
)

var namespace string

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate a report",
	Long:  `This command generates a report of the cluster's security posture.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Initialize Kubernetes client
		cfg, _ := k8s.InitClient()
		controlchecks.FetchVulnerabilityReports(context.Context, cfg, namespace)
	},
}

func init() {
	reportCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "The namespace to generate the report for")
	rootCmd.AddCommand(reportCmd)
}
