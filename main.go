package main

import (
	"context"
	"fmt" // Adjust this import to match your project's structure
	"kspm/pkg/entity"
	rbac "kspm/pkg/entity"
	watcher "kspm/pkg/k8s"
	"kspm/pkg/riskposture"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// calls securityRoles and flaggedPermissions from entity package
var securityRoles []rbac.RBACRoleList
var flaggedPermissions [][]rbacv1.PolicyRule

// main is the entry point of the program.
// main is the entry point of the program.
func main() {

	// Initialize the Kubernetes client
	kubeconfig := os.Getenv("KUBECONFIG")
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating in-cluster config: %v\n", err)
		os.Exit(1)
	}
	clientset, err := kubernetes.NewForConfig(config) // Add missing variable declaration for clientset
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating Kubernetes client: %v\n", err)
		os.Exit(1)
	}

	// Define the watchCmd variable
	color.New(color.BgHiCyan).Println("Starting KSPM...")
	color.New(color.BgHiRed).Println("Please select an option:")
	color.New(color.FgBlue).Println("1. Watch Kubernetes resources")
	color.New(color.FgGreen).Println("2. Run control checks")
	color.New(color.FgYellow).Println("3. Check deployments for violations of no labels")
	color.New(color.FgRed).Println("4. Display risk levels")
	color.New(color.FgHiCyan).Println("5. Rbac Analysis")
	fmt.Print("Enter the number of the option you want to select: ")

	var option int
	for {
		_, err := fmt.Scanf("%d", &option)
		if err != nil {
			fmt.Println(err)
			return
		}
		break // Add a break statement to exit the loop after reading user input
	}

	// Check the option selected by the user
	if option == 1 {
		watchCmd := &cobra.Command{
			Use:   "watch",
			Short: "Start watching Kubernetes resources",
			Long:  `Starts the Kubernetes watcher to monitor resources.`,
			Run: func(cmd *cobra.Command, args []string) {
				color.Green("Starting Kubernetes watcher...")
				// Initialize Kubernetes client
				watcher.WatchPods(clientset) // Passes clientset to the WatchPods function
			},
		}
		watchCmd.Execute()
		// Execute the watch command
	} else if option == 2 {
		// Define the checkCmd variable
		checkCmd := &cobra.Command{
			Use:   "check",
			Short: "Run control checks",
			Long:  `Runs the control checks against the cluster.`,
			Run: func(cmd *cobra.Command, args []string) {
				color.Green("Running control checks...")
				// Initialize Kubernetes client
				_, err := clientset.RbacV1().Roles("").List(cmd.Context(), metav1.ListOptions{})
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error fetching roles: %v\n", err)
					os.Exit(1)
				}
			},
		}
		checkCmd.Execute() // Execute the check command
	} else if option == 3 {
		// Define the deploymentCmd variable
		deploymentCmd := &cobra.Command{
			Use:   "deployment",
			Short: "Run deployment checks",
			Long:  `Runs the deployment checks against the cluster.`,
			Run: func(cmd *cobra.Command, args []string) {
				color.Green("Running deployment checks...")
				// Initialize Kubernetes client
				deployments, err := clientset.AppsV1().Deployments("").List(cmd.Context(), metav1.ListOptions{})
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error fetching deployments: %v\n", err)
					os.Exit(1)
				}
				// Call the custom function
				deploymentList, violationCount := rbac.NewDeploymentList(deployments)
				fmt.Printf("Number of deployments with no labels: %d\n", violationCount)
				for _, deployment := range deploymentList {
					fmt.Printf("Name: %s, Namespace: %s, Replicas: %d, Labels: %v\n", deployment.Name, deployment.Namespace, deployment.Replicas, deployment.Labels)
				}
			},
		}
		deploymentCmd.Execute()
	} else if option == 4 {
		// Fetch the list of roles from the Kubernetes API
		roleList, err := clientset.RbacV1().Roles("").List(context.Background(), metav1.ListOptions{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to fetch RBAC roles: %v\n", err)
			return
		}
		// Print the roles
		// Declare the functions variable
		var functions []riskposture.Function

		for _, role := range roleList.Items {
			cyan := color.New(color.FgCyan).SprintFunc()
			yellow := color.New(color.FgYellow).SprintFunc()
			fmt.Printf("%s, NS: %s, Permissions: %v, Resources: %v\n",
				cyan(role.Name),
				yellow(role.Namespace),
				cyan(role.Rules),
				yellow(role.APIVersion))
		}

		// Call the NewRBACRoleList function with the roles from roleList
		roles, _ := rbac.NewRBACRoleList(roleList.Items)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error in NewRBACRoleList: %v\n", err)
			return
		}

		// Convert roles to a slice of riskposture.Function
		for _, role := range roles {
			roleFunctions := rbac.ConvertRoleToFunction(role, [][]rbac.PolicyRule{})
			functions = append(functions, roleFunctions...)
		}

		// Create a new RiskPosture with the roleFunctions
		riskPostureInstance := riskposture.NewRiskPosture(functions)
		// Display the risk levels
		riskPostureInstance.DisplayRiskLevels()
	} else if option == 5 {
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
		rbacCmd := &cobra.Command{
			Use:   "rbac",
			Short: "Run RBAC Checks",
			Long:  `Runs RBAC checks against the cluster.`,
			Run: func(cmd *cobra.Command, args []string) {
				color.Green("Running RBAC checks...")
				// Display the converted roles
				for _, role := range allRoles {
					cyan := color.New(color.FgCyan).SprintFunc()
					yellow := color.New(color.FgYellow).SprintFunc()
					for _, rule := range role.Rules { // Assuming that your RBACRole has a method GetRules() that returns []rbacv1.PolicyRule
						fmt.Printf("Name: %s, NS: %s, Permissions: %v, Resources: %v\n",
							cyan(role.Name),
							yellow(role.Namespace),
							cyan(rule.Verbs),
							yellow(rule.Resources))
					}
				}
			},
		}
		rbacCmd.Execute()
	} else {
		fmt.Println("Invalid option")
	}
} // Add a closing brace here
