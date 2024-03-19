package main

import (
	"context"
	"fmt" // Adjust this import to match your project's structure
	"kspm/pkg/controlchecks"
	"kspm/pkg/entity"
	rbac "kspm/pkg/entity"
	watcher "kspm/pkg/k8s"
	"kspm/pkg/reports"
	"kspm/pkg/trivytypes"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	// Adjust this import to match your project's structure
)

func initClient() (*kubernetes.Clientset, error) {
	var config *rest.Config
	var err error

	// Try to use the in-cluster configuration (if exists)
	config, err = rest.InClusterConfig()
	if err != nil {
		// If in-cluster configuration does not exist, try to use the local configuration
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			kubeconfig = filepath.Join(os.Getenv("HOME"), ".kube", "config")
		}
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("failed to build config: %w", err)
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	return clientset, nil
}

var (
	watchFlag      bool
	checkFlag      bool
	deploymentFlag bool
	riskFlag       bool
	rbacFlag       bool
	imageFlag      string
	namespace      string
	rootCmd        = &cobra.Command{
		Use:   "paranoia",
		Short: "Paranoia is a tool for monitoring and securing Kubernetes clusters",
	}
)

func init() {
	rootCmd.PersistentFlags().BoolVarP(&watchFlag, "watch", "w", false, "Start watching Kubernetes resources")
	rootCmd.PersistentFlags().BoolVarP(&checkFlag, "check", "c", false, "Run control checks")
	rootCmd.PersistentFlags().BoolVarP(&deploymentFlag, "deployment", "d", false, "Run deployment checks")
	rootCmd.PersistentFlags().BoolVarP(&riskFlag, "risk", "r", false, "Run risk checks")
	rootCmd.PersistentFlags().BoolVarP(&rbacFlag, "rbac", "b", false, "Run RBAC checks")
	rootCmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", "", "The name of the image to scan")

	rootCmd.AddCommand(createWatchCmd())
	rootCmd.AddCommand(createCheckCmd())
	rootCmd.AddCommand(createDeploymentCmd())
	rootCmd.AddCommand(createRbacCmd())
	rootCmd.AddCommand(reportCmd())
}

// Define the watch command in the init to be accessible from the root command
func createWatchCmd() *cobra.Command {
	var watchFlag bool // Initialize watchFlag as a boolean variable
	var watchCmd = &cobra.Command{
		Use:   "watch",
		Short: "Start watching Kubernetes resources",
		Long:  `Starts the Kubernetes watcher to monitor resources.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Get the flag value
			flagValue, _ := cmd.Flags().GetBool("watch")

			// Check the flag value
			if flagValue {
				color.Green("Starting Kubernetes watcher...........")
				// Initialize client
				clientset, err := initClient()
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error initializing Kubernetes client: %v\n", err)
					os.Exit(1)
				}
				// Start the watcher
				watcher.WatchPods(clientset)
			} else {
				color.Green("Watch flag is false............")
			}
		},
	}
	watchCmd.Flags().BoolVarP(&watchFlag, "watch", "w", false, "Start watching Kubernetes resources")
	return watchCmd
}
func createCheckCmd() *cobra.Command {
	var checkFlag bool
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
			if checkFlag {
				color.Green("Running control checks...")
				clusterRoles, err := clientset.RbacV1().ClusterRoles().List(cmd.Context(), metav1.ListOptions{})
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error fetching cluster roles: %v\n", err)
					os.Exit(1)
				}
				requiredRoles := []string{
					"system:auth-delegator",
					"system:certificates.k8s.io:certificatesigningrequests:nodeclient",
					"system:aggregate-to-admin",
				}
				color.New(color.BgHiYellow).Printf("Searching for required roles: %v\n", requiredRoles)
				for _, requiredRole := range requiredRoles {
					found := false
					for _, clusterRole := range clusterRoles.Items {
						if clusterRole.Name == requiredRole {
							found = true
							break
						}
					}
					if found {
						color.New(color.BgGreen).Printf("Required cluster role %s found\n", requiredRole)
					} else {
						color.New(color.BgHiMagenta).Printf("Required cluster role %s not found\n", requiredRole)
					}
				}
				// check for pods in a certain state
				pods, err := clientset.CoreV1().Pods("").List(cmd.Context(), metav1.ListOptions{})
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error fetching pods: %v\n", err)
					os.Exit(1)
				}
				for _, pod := range pods.Items {
					if pod.Status.Phase != corev1.PodRunning {
						fmt.Printf("Pod %s is not running\n", pod.Name)
						os.Exit(1)
					}
				}

				// Checks for available nodes
				nodes, err := clientset.CoreV1().Nodes().List(cmd.Context(), metav1.ListOptions{})
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error fetching nodes: %v\n", err)
					os.Exit(1)
				}
				requiredNodeCount := 3
				if len(nodes.Items) < requiredNodeCount {
					fmt.Printf("Insufficient nodes: %d available, %d required\n", len(nodes.Items), requiredNodeCount)
					os.Exit(1)
				}
			} else {
				color.Green("Check flag is false............")
			}
		},
	}
	checkCmd.Flags().BoolVarP(&checkFlag, "check", "c", false, "Run control checks")
	return checkCmd
}
func createDeploymentCmd() *cobra.Command {
	var deploymentFlag bool
	var deploymentCmd = &cobra.Command{
		Use:   "deployment",
		Short: "Run deployment checks",
		Long:  `Runs the deployment checks against the cluster.`,
		Run: func(cmd *cobra.Command, args []string) {
			clientset, err := initClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error initializing Kubernetes client: %v\n", err)
				os.Exit(1)
			}
			color.Green("Running deployment checks...")
			deployments, err := clientset.AppsV1().Deployments("").List(cmd.Context(), metav1.ListOptions{})
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error fetching deployments: %v\n", err)
				os.Exit(1)
			}
			deploymentList, violationCount := entity.NewDeploymentList(deployments)
			fmt.Printf("Number of deployments with no labels: %d\n", violationCount)
			for _, deployment := range deploymentList {
				fmt.Printf("Name: %s, Namespace: %s, Replicas: %d, Labels: %v\n", deployment.Name, deployment.Namespace, deployment.Replicas, deployment.Labels)
			}
		},
	}
	deploymentCmd.Flags().BoolVarP(&deploymentFlag, "deployment", "d", false, "Run deployment checks")
	return deploymentCmd
}
func createRbacCmd() *cobra.Command {
	var rbacFlag bool
	var rbacCmd = &cobra.Command{
		Use:   "rbac",
		Short: "Run RBAC Checks",
		Long:  `Runs RBAC checks against the cluster.`,
		Run: func(cmd *cobra.Command, args []string) {
			if !rbacFlag {
				color.Green("RBAC flag is false............")
				return
			}
			clientset, err := initClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error initializing Kubernetes client: %v\n", err)
				os.Exit(1)
			}
			// Fetch the list of roles from the Kubernetes API
			roleList, err := clientset.RbacV1().Roles("").List(context.Background(), metav1.ListOptions{})
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to fetch roles: %v\n", err)
				return
			}

			// ClusterRoles
			clusterRoleList, err := clientset.RbacV1().ClusterRoles().List(context.Background(), metav1.ListOptions{})
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to fetch ClusterRoles: %v\n", err)
				return
			}

			// Convert the clusterRoleList.Items to custom role types
			clusterRoles, _ := rbac.NewRBACClusterRoleList(clusterRoleList.Items) // Removed err

			// Convert roles and clusterRoles to [][]rbacv1.PolicyRule before passing to PrintExcessPrivileges
			var policyRules [][]rbacv1.PolicyRule
			for _, role := range roleList.Items {
				policyRules = append(policyRules, role.Rules)
			}
			for _, clusterRole := range append(clusterRoles, securityRoles...) {
				// Retrieve the rules from the clusterRole
				entityRules := clusterRole.Rules

				// Convert entityRules to []rbacv1.PolicyRule
				var rbacRules []rbacv1.PolicyRule
				for _, entityRule := range entityRules {
					rbacRule := rbacv1.PolicyRule{
						Verbs:     entityRule.Verbs,
						Resources: entityRule.Resources,
						// Add other fields as necessary
					}
					rbacRules = append(rbacRules, rbacRule)
				}

				// Append the rules to policyRules
				policyRules = append(policyRules, rbacRules)
			}

			// Convert policyRules to [][]entity.PolicyRule
			var entityPolicyRules [][]entity.PolicyRule
			for _, rules := range policyRules {
				var entityRules []entity.PolicyRule
				for _, rule := range rules {
					// Convert rbacv1.PolicyRule to entity.PolicyRule
					entityRule := entity.PolicyRule{
						APIGroups: rule.APIGroups,
						Verbs:     rule.Verbs,
						Resources: rule.Resources,
						// Add other fields as necessary
					}
					entityRules = append(entityRules, entityRule)
				}
				entityPolicyRules = append(entityPolicyRules, entityRules)
			}

			rbac.PrintExcessPrivileges(entityPolicyRules) // Changed rbrbacvertPolicyRules to entityPolicyRules
			color.Green("Running RBAC checks...")
			// Display the converted roles
			// Display the converted roles
			var allRoles []rbacv1.Role
			allRoles = append(allRoles, roleList.Items...)
			for _, clusterRole := range clusterRoleList.Items {
				role := rbacv1.Role{
					ObjectMeta: clusterRole.ObjectMeta,
					Rules:      clusterRole.Rules,
				}
				allRoles = append(allRoles, role)
			}
			// ... // Changed rbrbacvertPolicyRules to entityPolicyRules
			// Display the converted roles

			for _, role := range allRoles {
				cyan := color.New(color.FgCyan).SprintFunc()
				yellow := color.New(color.FgYellow).SprintFunc()
				for _, rule := range role.Rules { // Assuming that your RBACRole has a method GetRules() that returns []rbacv1.PolicyRule
					ns := role.Namespace
					if ns == "" {
						ns = "No Namespace - ClusterRole"
					}
					var coloredVerbs []string
					for _, verb := range rule.Verbs {
						if verb == "create" || verb == "delete" || verb == "update" || verb == "patch" {
							coloredVerbs = append(coloredVerbs, color.New(color.FgRed).SprintFunc()(verb))
						} else {
							coloredVerbs = append(coloredVerbs, verb)
						}
					}
					fmt.Printf("Name: %s, NS: %s, Permissions: %v, Resources: %v\n",
						cyan(role.Name),
						yellow(ns),
						coloredVerbs,
						yellow(rule.Resources))
				} // Closing brace for the inner for loop
			} // Closing brace for the outer for loop
		}, // Closing brace for the Run function
	} // Closing brace for the rbacCmd definition
	// Add the watch command to the root command
	rbacCmd.Flags().BoolVarP(&rbacFlag, "rbac", "b", false, "Run RBAC checks")
	return rbacCmd
}
func reportCmd() *cobra.Command {
	var namespace string
	var kubeconfig string

	var reportCmd = &cobra.Command{
		Use:   "report",
		Short: "Scan images for vulnerabilities",
		Long:  `Scans the images for vulnerabilities.`,
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error getting Kubernetes config: %v\n", err)
				os.Exit(1)
			}

			ctx := context.Background()

			if namespace == "" {
				fmt.Fprintf(os.Stderr, "Namespace is required\n")
				os.Exit(1)
			}

			vulnReports, err := controlchecks.FetchVulnerabilityReports(ctx, cfg, namespace)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error fetching vulnerability reports: %v\n", err)
				os.Exit(1)
			}

			var vulns []trivytypes.Vulnerability
			fmt.Printf("Number of reports: %d\n", len(vulnReports))
			for _, trivyReport := range vulnReports {
				for _, trivyVuln := range trivyReport.Report.Vulnerabilities {
					reportVuln := trivytypes.Vulnerability{
						VulnerabilityID: trivyVuln.VulnerabilityID,
						Description:     trivyVuln.Description,
					}
					vulns = append(vulns, reportVuln)
				}
			}
			// Call PrintVulnerabilityTable inside the Run function
			reports.PrintVulnerabilityTable(vulns)
		},
	}

	reportCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "The namespace to fetch reports from")
	reportCmd.Flags().StringVarP(&kubeconfig, "kubeconfig", "k", "", "Path to the kubeconfig file")
	return reportCmd
} // Closing brace for the imageScanCmd

// calls securityRoles and flaggedPermissions from entity package
var securityRoles []rbac.RBACRoleList

// main is the entry point of the program.
func main() {
	// Initialize Kubernetes client
	_, err := initClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing Kubernetes client: %v\n", err)
		os.Exit(1)
	}

	// Execute the root command
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error executing command: %v\n", err)
		os.Exit(1)
	}
}
