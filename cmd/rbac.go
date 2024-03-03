package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	entity "kspm/pkg/entity"
)

var visualizeFlag bool

var rbacCmd = &cobra.Command{
	Use:   "rbac",
	Short: "Run RBAC checks",
	Long:  `Runs the RBAC checks against the cluster.`,
	Run: func(cmd *cobra.Command, args []string) {
		displaySecurityRoles()
	},
}

func init() {
	rootCmd.AddCommand(rbacCmd)

}

func displaySecurityRoles() {
	// Load the kubeconfig file to connect to the Kubernetes cluster
	clientset, err := initClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create Kubernetes client: %v\n", err)
		return
	}

	// Fetch RBAC roles using the clientset
	roles, err := clientset.RbacV1().Roles("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to fetch RBAC roles: %v\n", err)
		return
	}

	// Convert the fetched roles to your custom SecurityRoleList
	securityRoles, flaggedPermissions := entity.NewRBACRoleList(roles.Items)

	// Display the converted roles
	for i, role := range securityRoles {
		fmt.Printf("Name: %s, NS: %s, Permissions: %v, Resources: %v\n",
			role.Name, role.Namespace, role.Permissions, role.Resources)
		if len(flaggedPermissions[i]) > 0 {
			fmt.Printf("Flagged Permissions: %v\n", flaggedPermissions[i])
		}
	}
	// Visualize relationships between roles if the visualize flag is set
}
