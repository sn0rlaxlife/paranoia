package main

import (
	"fmt" // Adjust this import to match your project's structure
	rbac "kspm/pkg/entity"
	watcher "kspm/pkg/k8s"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// main is the entry point of the program.
func main() {
	// Define the watchCmd variable
	fmt.Println("Starting KSPM...")
	fmt.Println("Please select an option:")
	fmt.Println("1. Watch Kubernetes resources")
	fmt.Println("2. Run control checks")

	var option int
	_, err := fmt.Scanf("%d", &option)
	if err != nil {
		fmt.Println(err)
		return
	}

	if option == 1 {
		watchCmd := &cobra.Command{
			Use:   "watch",
			Short: "Start watching Kubernetes resources",
			Long:  `Starts the Kubernetes watcher to monitor resources.`,
			Run: func(cmd *cobra.Command, args []string) {
				color.Green("Starting Kubernetes watcher...")
				// Initialize Kubernetes client
				kubeconfig := os.Getenv("KUBECONFIG")
				config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error creating in-cluster config: %v\n", err)
					os.Exit(1)
				}
				clientset, err := kubernetes.NewForConfig(config)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error creating Kubernetes client: %v\n", err)
					os.Exit(1)
				}
				watcher.WatchPods(clientset) // Passes clientset to the WatchPods function
			},
		}
		watchCmd.Execute() // Execute the watch command
	}
	if option == 2 {
		// Define the checkCmd variable
		checkCmd := &cobra.Command{
			Use:   "check",
			Short: "Run control checks",
			Long:  `Runs the control checks against the cluster.`,
			Run: func(cmd *cobra.Command, args []string) {
				color.Green("Running control checks...")
				// Initialize Kubernetes client
				kubeconfig := os.Getenv("KUBECONFIG")
				config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error creating in-cluster config: %v\n", err)
					os.Exit(1)
				}
				clientset, err := kubernetes.NewForConfig(config)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error creating Kubernetes client: %v\n", err)
					os.Exit(1)
				}
				roleList, err := clientset.RbacV1().Roles("").List(cmd.Context(), metav1.ListOptions{})
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error fetching roles: %v\n", err)
					os.Exit(1)
				}

				// Call custom function
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error in RBACList: %v\n", err)
					os.Exit(1)
				}
				// fetch the list of roles from the Kubernetes API
				securityRoles := rbac.NewRBACRoleList(roleList.Items)

				// display the roles
				for _, role := range securityRoles {
					fmt.Printf("Name: %s, Namespace: %s, Permissions: %v, Resources: %v\n", role.Name, role.Namespace, role.Permissions, role.Resources)
				}
			},
		}
		checkCmd.Execute()
	}
}
