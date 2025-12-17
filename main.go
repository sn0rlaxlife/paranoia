package main

import (
	"context"
	"fmt"
	"kspm/pkg/controlchecks"
	"kspm/pkg/entity"
	"kspm/pkg/k8s"
	"kspm/pkg/reports"
	"kspm/pkg/riskposture"
	"kspm/pkg/trivytypes"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"

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
	watchPodsFlag         bool
	watchDeploymentsFlag  bool
	watchSecretsFlag      bool
	watchClusterRolesFlag bool
	watchFlag             bool
	//checkFlag             bool
	deploymentFlag bool
	riskFlag       bool
	rbacFlag       bool
	namespace      string
	rootCmd        = &cobra.Command{
		Use:   "paranoia",
		Short: "Paranoia is a tool for monitoring and securing Kubernetes clusters",
	}
)

// Declare secRoles with correct Type
var securityRoles entity.RBACRoles

func init() {
	rootCmd.PersistentFlags().BoolVar(&watchPodsFlag, "watch-pods", false, "Watch Pods")
	rootCmd.PersistentFlags().BoolVar(&watchDeploymentsFlag, "watch-deployments", false, "Watch Deployments")
	rootCmd.PersistentFlags().BoolVar(&watchSecretsFlag, "watch-secrets", false, "Watch Secrets")
	rootCmd.PersistentFlags().BoolVar(&watchClusterRolesFlag, "watch-clusterroles", false, "Watch ClusterRoles")
	//rootCmd.PersistentFlags().BoolVarP(&checkFlag, "check", "c", false, "Run control checks")
	rootCmd.PersistentFlags().BoolVarP(&deploymentFlag, "deployment", "d", false, "Run deployment checks")
	rootCmd.PersistentFlags().BoolVarP(&riskFlag, "risk", "r", false, "Run risk checks")
	rootCmd.PersistentFlags().BoolVarP(&rbacFlag, "rbac", "b", false, "Run RBAC checks")
	rootCmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", "", "The name of the image to scan")

	rootCmd.AddCommand(createWatchCmd())
	rootCmd.AddCommand(createCheckCmd())
	rootCmd.AddCommand(createDeploymentCmd())
	rootCmd.AddCommand(createRbacCmd())
	rootCmd.AddCommand(reportCmd())
	rootCmd.AddCommand(reportHTMLCmd())
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
			//flagValue, _ := cmd.Flags().GetBool("watch")

			flagValue := watchFlag

			// Check if one resource is selected for watch flag
			resourceSelected := watchPodsFlag ||
				watchDeploymentsFlag ||
				watchSecretsFlag ||
				watchClusterRolesFlag

			if !resourceSelected {
				color.Yellow("No resources selected for watch....Please specify at least one resource")
				color.Yellow("  --watch-pods")
				color.Yellow("  --watch-deployments")
				color.Yellow("  --watch-secrets")
				color.Yellow("  --watch-clusterroles")
				return
			}

			// Check the flag value
			if flagValue {
				color.Green("Starting Kubernetes watcher...........")
				// Initialize client
				clientset, err := initClient()
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error initializing Kubernetes client: %v\n", err)
					os.Exit(1)
				}
				// watch Options
				watchOptions := map[string]bool{
					"pods":         watchPodsFlag,
					"deployments":  watchDeploymentsFlag,
					"secrets":      watchSecretsFlag,
					"clusterRoles": watchClusterRolesFlag,
				}

				// Print the reosurces that are selected for watch
				color.Yellow("Resources being watched:")
				for resource, enabled := range watchOptions {
					if enabled {
						color.Green("  %s", resource)
					}
				}

				// Adding debugging code before calls
				fmt.Println("Debug: About to start watchers with options:", watchOptions)

				// Stop channels
				stopChannels := k8s.StartKubernetesWatchers(clientset, watchOptions)

				// Catching signal
				fmt.Printf("Debug: Received %d stop channels\n", len(stopChannels))

				if len(stopChannels) == 0 {
					color.Yellow("No resources selected for watch....Check the flags")
					return
				}

				// Start signal handling for ops
				color.Green("Watchers started. Press Ctrl+C to stop")

				// Set up signal handling for graceful shutdown
				sigCh := make(chan os.Signal, 1)
				signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
				<-sigCh
				color.Yellow("Shutting down watchers...")
				// Stop all watchers
				for i, stop := range stopChannels {
					fmt.Printf("Debug: Closing Stop Channel %d\n", i)
					close(stop)
				}
				// Start the watcher
				//watcher.WatchPods(clientset)
				//watcher.WatchClusterRoles(clientset)
				//watcher.WatchNamespaces(clientset) // Add this line to watch namespaces
				//watcher.WatchDeployments(clientset) // Add this line to watch deployments
				//watcher.WatchSecrets(clientset)     // Add this line to watch secrets
				//watcher.CheckClusterRoleSecurity(clientset) // Add this line to check cluster role security
				//watcher.CheckServiceAccountSecrets(clientset) // Add this line to check service account secrets
				//watcher.CheckDeploymentSecurity(clientset) // Add this line to check deployment security
				//watcher.CheckPodSecurityWithReporting(clientset) // Add this line to check pod security with reporting
				//watcher.StartKubernetesWatchers(clientset) // Add this line to start all watchers
			} else {
				color.Green("Watch flag is false............")
			}
		},
	}
	watchCmd.Flags().BoolVarP(&watchFlag, "watch", "w", false, "Start watching Kubernetes resources")
	return watchCmd
}
func createCheckCmd() *cobra.Command {
	// - Removed for temporary reassessment // var checkFlag bool
	var checkCmd = &cobra.Command{
		Use:   "check",
		Short: "Run control checks",
		Long:  `Runs the control checks against the cluster.`,
		Run: func(cmd *cobra.Command, args []string) {
			// if !checkFlag {
			// Initialize Kubernetes client
			clientset, err := initClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error initializing Kubernetes client: %v\n", err)
				os.Exit(1)
			}
			// Execute checks if flag is true
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
			color.Green("All control checks passed successfully.")
		},
	}
	//checkCmd.Flags().BoolVarP(&checkFlag, "check", "c", false, "Run control checks")
	return checkCmd
}
func createDeploymentCmd() *cobra.Command {
	// - Reassessment of this use 12-14-25 // var deploymentFlag bool
	var deploymentCmd = &cobra.Command{
		Use:   "deployment",
		Short: "Run deployment checks",
		Long:  `Runs the deployment checks against the cluster.`,
		Run: func(cmd *cobra.Command, args []string) {
			if !deploymentFlag {
				color.Green("Deployment flag is false............")
				return
			}
			clientset, err := initClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error initializing Kubernetes client: %v\n", err)
				os.Exit(1)
			}
			color.Green("Running deployment checks...")
			deploymentList, violationCount, err := entity.GetDeploymentsAndViolationCount(clientset)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				os.Exit(1)
			}
			green := color.New(color.FgGreen).SprintFunc()
			red := color.New(color.FgHiRed).SprintFunc()
			blue := color.New(color.FgHiBlue).SprintFunc()
			cyan := color.New(color.FgHiCyan).SprintFunc()
			fmt.Printf("%s: %d\n", red("Number of deployments with no labels"), violationCount)
			for _, deployment := range deploymentList {
				fmt.Printf("Name: %s, Namespace: %s, Replicas: %s\n",
					green(deployment.Name),
					blue(deployment.Namespace),
					cyan(deployment.Replicas))

				labels := make([]string, 0, len(deployment.Labels))
				for key, value := range deployment.Labels {
					labels = append(labels, fmt.Sprintf("%s: %s", key, value))
				}
				fmt.Printf("Labels: %s\n", blue(strings.Join(labels, ", ")))
				fmt.Println()
			}
		},
	}
	// -- Reasses 12-14-25 -- deploymentCmd.Flags().BoolVarP(&deploymentFlag, "deployment", "d", false, "Run deployment checks")
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

			// Create a new tabwriter.Writer
			w := new(tabwriter.Writer)
			// Initialize the writer to write to os.Stdout with specific formatting parameters
			w.Init(os.Stdout, 0, 8, 2, '\t', 0)

			// Print the headers of the table
			fmt.Fprintln(w, "Role\tNamespace\tVerb\tRisk")

			// Create color functions for red and green
			red := color.New(color.FgRed).SprintFunc()
			green := color.New(color.FgGreen).SprintFunc()
			yellow := color.New(color.FgYellow).SprintFunc()
			hired := color.New(color.FgHiRed).SprintFunc()

			// Iterate over the roles
			for _, role := range roleList.Items {
				// Iterate over the rules of each role
				for _, rule := range role.Rules {
					// If the verbs of the rule are considered dangerous
					if entity.HasDangerousVerbs(rule.Verbs) {
						// Print the role's details with the status "Dangerous"
						for _, verb := range rule.Verbs {
							fmt.Fprintf(w, "%s\t%-70s\t%-70s\t%s\n", red(role.Name), green(role.Namespace), yellow(verb), hired("Dangerous"))
						}
					}
					// If the verbs of the rule contain a wildcard
					if entity.HasWildcard(rule.Verbs) {
						// Print the role's details with the status "Wildcard"
						for _, verb := range rule.Verbs {
							fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", red(role.Name), green(role.Namespace), verb, "Wildcard")
						}
					}
				}
			}

			// Flush the writer to ensure all output is written and aligned
			w.Flush()
			// Convert the clusterRoleList.Items to custom role types
			var clusterRoleList rbacv1.ClusterRoleList
			clusterRoles, _ := entity.NewRBACClusterRoleList(clusterRoleList.Items)
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
						// API Groups, Verbs, and Resources are the only fields required for the conversion
						APIGroups: rule.APIGroups,

						// Verbs represents a list of vers this rule applies to
						Verbs: rule.Verbs,

						// Resources represents a list of resources this rule applies to
						Resources: rule.Resources,
						// Add other fields as necessary
					}
					entityRules = append(entityRules, entityRule)
				}
				entityPolicyRules = append(entityPolicyRules, entityRules)
			}

			entity.PrintExcessPrivileges(entityPolicyRules) // Changed rbrbacvertPolicyRules to entityPolicyRules
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
				for _, rule := range role.Rules {
					ns := role.Namespace
					if ns == "" {
						ns = "ClusterRole"
					}
					entityRule := entity.PolicyRule(rule)
					permissions, resources, _, err := entity.ExtractPermissionsAndResources(entityRule)
					if err != nil {
						log.Printf("Error extracting permissions and resources: %v\n", err)
						continue
					}
					var coloredVerbs []string
					for _, verb := range permissions {
						if verb == "create" || verb == "delete" || verb == "update" || verb == "patch" {
							coloredVerbs = append(coloredVerbs, color.New(color.FgRed).SprintFunc()(verb))
						} else {
							coloredVerbs = append(coloredVerbs, verb)
						}
					}
					fmt.Printf("%s, NS: %s, Permissions: %v, Resources: %v\n",
						cyan(role.Name),
						yellow(ns),
						coloredVerbs,
						yellow(resources))
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

func reportHTMLCmd() *cobra.Command {
	var outputPath string
	var kubeconfig string
	var port string
	var namespace string

	var reportHTMLCmd = &cobra.Command{
		Use:   "report-html",
		Short: "Generate comprehensive HTML security report of all findings in the cluster",
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to initialize Kubernetes configuration\n")
				os.Exit(1)
			}

			clientset, err := kubernetes.NewForConfig(cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to create Kubernetes client\n")
				os.Exit(1)
			}

			recorder := &k8s.RecordingSecurityEventHandler{}
			k8s.SetSecurityEventHandler(recorder)

			var allFindings []string
			var allSignals []riskposture.Signal
			var rbacFindings, deploymentFindings, controlPlaneFindings, podFindings, secretFindings []string
			ctx := context.Background()

			// Pod Security Checks
			pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Failed to list pods: %v\n", err)
			} else {
				for _, pod := range pods.Items {
					k8s.CheckPodSecurity(&pod)
				}
			}

			// RBAC Analysis
			clusterRoles, err := clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Failed to list cluster roles for RBAC analysis: %v\n", err)
			} else {
				for _, role := range clusterRoles.Items {
					// Skips system/built-in roles
					if strings.HasPrefix(role.Name, "system:") ||
						strings.HasPrefix(role.Name, "kubeadm:") ||
						strings.HasPrefix(role.Name, "k8s.io:") {
						continue
					}
					findings, signals, _ := entity.AnalyzeClusterRoles(clientset, role.Name)
					rbacFindings = append(rbacFindings, findings...)
					allFindings = append(allFindings, findings...)
					allSignals = append(allSignals, signals...)
				}
			}

			// Deployment label violations
			_, violationCount, err := entity.GetDeploymentsAndViolationCount(clientset)
			if err == nil && violationCount > 0 {
				finding := fmt.Sprintf("[MEDIUM] %d deployments missing labels", violationCount)
				deploymentFindings = append(deploymentFindings, finding)
				allFindings = append(allFindings, finding)
				allSignals = append(allSignals, riskposture.Signal{
					Name:     "DeploymentMissingLabels",
					Severity: "MEDIUM",
					Weight:   10,
				})
			}

			// Control plane checks
			requiredRoles := []string{
				"system:auth-delegator",
				"system:certificates.k8s.io:certificatesigningrequests:nodeclient",
				"system:aggregate-to-admin",
			}
			for _, requiredRole := range requiredRoles {
				_, err := clientset.RbacV1().ClusterRoles().Get(ctx, requiredRole, metav1.GetOptions{})
				if err != nil {
					finding := fmt.Sprintf("[HIGH] Required ClusterRole %s not found", requiredRole)
					controlPlaneFindings = append(controlPlaneFindings, finding)
					allFindings = append(allFindings, finding)
					allSignals = append(allSignals, riskposture.Signal{
						Name:     "MissingRequiredClusterRole",
						Severity: "HIGH",
						Weight:   15,
					})
				}
			}

			// Deployment Security Checks
			deployments, err := clientset.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Failed to list deployments: %v\n", err)
			} else {
				for _, deployment := range deployments.Items {
					k8s.CheckDeploymentSecurity(&deployment)
				}
			}

			// ClusterRole Security Checks
			clusterRolesList, err := clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Failed to list cluster roles: %v\n", err)
			} else {
				for _, role := range clusterRolesList.Items {
					k8s.CheckClusterRoleSecurity(&role)
				}
			}

			// Secret Security Checks
			secrets, err := clientset.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Failed to list secrets: %v\n", err)
			} else {
				for _, secret := range secrets.Items {
					k8s.CheckSecretSecurity(&secret)
				}
			}

			// Convert recorded events to findings and categorize
			events := recorder.SnapShot()
			for _, event := range events {
				finding := fmt.Sprintf("[%s] %s/%s in %s: %s",
					event.Severity, event.ResourceType, event.ResourceName,
					event.Namespace, event.Message)

				switch event.ResourceType {
				case "Pod":
					podFindings = append(podFindings, finding)
				case "Deployment":
					deploymentFindings = append(deploymentFindings, finding)
				case "ClusterRole":
					rbacFindings = append(rbacFindings, finding)
				case "Secret":
					secretFindings = append(secretFindings, finding)
				}

				allFindings = append(allFindings, finding)
			}

			// Vulnerability Report Integration
			nsFlag := cmd.Flag("namespace").Value.String()
			if nsFlag != "" {
				vulnReports, err := controlchecks.FetchVulnerabilityReports(ctx, cfg, nsFlag)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Warning: Failed to fetch vulnerability reports: %v\n", err)
				} else {
					for _, report := range vulnReports {
						for _, vuln := range report.Report.Vulnerabilities {
							allFindings = append(allFindings, fmt.Sprintf("Vulnerability: %s - %s",
								vuln.VulnerabilityID, vuln.Description))
						}
					}
				}
			}

			if len(allFindings) == 0 {
				allFindings = append(allFindings, "No security findings detected")
			}

			fmt.Printf("HTML report will be generated at %s\n", outputPath)
			fmt.Printf("Total findings: %d\n", len(allFindings))

			// Merge signals
			//parsedSignals := riskposture.SignalsFromFindings(allFindings)
			//allSignals = append(allSignals, parsedSignals...)
			rp := riskposture.NewRiskPosture(allSignals)

			// Risk metrics
			counts := rp.CountRiskLevels()
			score, drivers := rp.Score()
			paths := rp.DeriveAttackPaths()
			fixes := rp.Remediations()

			view := reports.BuildReportView("Comprehensive Kubernetes Security Report", allFindings)
			view.RiskScore = score
			view.RiskCounts = counts
			view.RiskDrivers = drivers
			view.AttackPaths = paths
			view.Remediations = fixes
			view.RBACFindings = reports.CategorizeFindings(rbacFindings)
			view.DeploymentFindings = reports.CategorizeFindings(deploymentFindings)
			view.ControlPlaneFindings = reports.CategorizeFindings(controlPlaneFindings)
			view.PodFindings = reports.CategorizeFindings(podFindings)
			view.SecretFindings = reports.CategorizeFindings(secretFindings)

			// Console output
			fmt.Println("\n=== Risk Summary ===")
			fmt.Printf("Risk Score  : %d/100\n", score)
			fmt.Printf("Critical    : %d\n", counts.Critical)
			fmt.Printf("High        : %d\n", counts.High)
			fmt.Printf("Medium      : %d\n", counts.Medium)
			fmt.Printf("Low         : %d\n", counts.Low)

			if len(drivers) > 0 {
				fmt.Print("\nTop Risk Drivers:\n")
				for i, d := range drivers {
					if i >= 5 {
						break
					}
					fmt.Printf("- %s\n", d)
				}
			}

			if len(paths) > 0 {
				fmt.Println("\nAttack Paths Detected:")
				for _, p := range paths {
					fmt.Printf("  - [%s] %s (confidence %d%%)\n", p.Severity, p.Title, p.Confidence)
				}
			}

			if len(fixes) > 0 {
				fmt.Println("\nSuggested Fixes:")
				for _, fx := range fixes {
					fmt.Printf("  - [%s] %s\n", fx.Priority, fx.Title)
				}
			}

			err = reports.ServeHTMLReportView(view, outputPath, port)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to serve HTML report: %v\n", err)
				os.Exit(1)
			}
		},
	}
	reportHTMLCmd.Flags().StringVarP(&outputPath, "output", "o", "security-report.html", "Output path for the HTML report")
	reportHTMLCmd.Flags().StringVarP(&kubeconfig, "kubeconfig", "k", "", "Path to the kubeconfig file")
	reportHTMLCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Namespace for vulnerability scanning (optional)")
	reportHTMLCmd.Flags().StringVarP(&port, "port", "p", "8080", "Port to serve the HTML report")

	return reportHTMLCmd
}

// main is the entry point of the program.
func main() {
	// Execute the root command
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error executing command: %v\n", err)
		os.Exit(1)
	}
}
