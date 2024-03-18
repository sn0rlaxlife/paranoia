package cmd

import (
	"context"
	"fmt"
	"kspm/pkg/controlchecks"
	"kspm/pkg/entity"
	watcher "kspm/pkg/k8s"
	"kspm/pkg/riskposture"
	"os"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var kubeconfig *string

func initClient() (*kubernetes.Clientset, error) {
	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to build config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	return clientset, nil
}

var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Start watching Kubernetes resources",
	Long:  `Starts the Kubernetes watcher to monitor resources.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Initialize Kubernetes client
		clientset, err := initClient()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error initializing Kubernetes client: %v\n", err)
			os.Exit(1)
		}

		// Start the watcher function command
		watcher.WatchPods(clientset)
	},
}
var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Run control checks",
	Long:  `Runs the control checks against the cluster.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Initialize Kubernetes client
		clientset, err := initClient()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error initializing Kubernetes client: %v\n", err)
			os.Exit(1)
		}

		// Start the entity Kubernetes watcher
		entity.NewRBACRoleList(clientset)
	},
}
var deploymentCmd = &cobra.Command{
	Use:   "deployment",
	Short: "Run deployment checks",
	Long:  `Runs the deployment checks against the cluster.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Initialize Kubernetes client
		clientset, err := initClient()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error initializing Kubernetes client: %v\n", err)
			os.Exit(1)
		}

		// Fetch the list of deployments from the Kubernetes API
		deploymentList, err := clientset.AppsV1().Deployments("").List(cmd.Context(), metav1.ListOptions{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching deployments: %v\n", err)
			os.Exit(1)
		}

		// Start the entity Kubernetes watcher
		// Call the function
		deployments, violationCount := entity.NewDeploymentList(deploymentList)

		// Use the returned values
		fmt.Printf("Found %d deployments, %d of them have label violations\n", len(deployments), violationCount)
	},
}

var displayRiskLevelsCmd = &cobra.Command{
	Use:   "risk-levels",
	Short: "Display risk levels",
	Long:  `Displays the risk levels for the checks.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Initialize the client
		clientset, err := initClient()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error initializing Kubernetes client: %v\n", err)
			os.Exit(1)
		}

		// Fetch the list of roles from the Kubernetes API
		roleList, err := clientset.RbacV1().Roles("").List(cmd.Context(), metav1.ListOptions{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error listing roles: %v\n", err)
			os.Exit(1)
		}

		// Call the NewRBACRoleList Function with the roles from rolelist
		roles, err := rbac.NewRBACRoleList(roleList)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating RBAC role list: %v\n", err)
			os.Exit(1)
		}

		// Initialize the function
		var functions []riskposture.Function
		for _, role := range roles {
			roleFunctions := rbac.ConvertRoleToFunction(role, [][]rbac.PolicyRule{})
			functions = append(functions, roleFunctions...)
		}

		// Create a new RiskPosture with the functions
		riskPostureInstance := riskposture.NewRiskPosture(functions)

		// Display the risk levels
		riskPostureInstance.DisplayRiskLevels()
	},
}

var reportCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan images for vulnerabilities",
	Long:  `Scans the images for vulnerabilities.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Flag will be declared here for inputs
		cfg, err := rest.InClusterConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting Kubernetes config: %v\n", err)
			os.Exit(1)
		}

		ctx := context.Background()
		namespace := cmd.Flag("namespace").Value.String() // Make sure namespace is defined or fetched from flags

		if namespace == "" {
			fmt.Fprintf(os.Stderr, "Namespace is required\n")
			os.Exit(1)
		}

		reports, err := controlchecks.FetchVulnerabilityReports(ctx, cfg, namespace)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching vulnerability reports: %v\n", err)
			os.Exit(1)
		}

		// Do something with the reports...
		fmt.Println("Starting to print reports...")
		for _, report := range reports {
			fmt.Printf("Report: %v\n", report)
		}
	},
}

func init() {
	rootCmd.AddCommand(watchCmd)
	rootCmd.AddCommand(checkCmd)
	rootCmd.AddCommand(deploymentCmd)
	rootCmd.AddCommand(displayRiskLevelsCmd)
	rootCmd.AddCommand(rbacCmd)
	rootCmd.AddCommand(reportCmd)
	// Here you will define your flags and configuration settings.
	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// rootCmd.PersistentFlags().String("foo", "", "A help for foo")

}
