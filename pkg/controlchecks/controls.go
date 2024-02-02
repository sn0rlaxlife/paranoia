package controlchecks

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	rbac "k8s.io/kubernetes/pkg/apis/rbac"
)

type ControlCheckResult struct {
	Name        string
	IsCompliant bool
	Message     string
}

var results []ControlCheckResult
var isCompliant bool

func GetPermissionsFromRole(role *rbac.Role) string {
	var permissions []string

	for _, rule := range role.Rules {
		// Process rule to get permissions
		perm := fmt.Sprintf("verbs: [%s], resources: [%s]", strings.Join(rule.Verbs, ", "), strings.Join(rule.Resources, ", "))
		permissions = append(permissions, perm)
	}
	// Join all permissions into a single string
	return strings.Join(permissions, "; ")
}

func getRoles(clientset *kubernetes.Clientset) ([]*rbacv1.Role, error) {
	roleList, err := clientset.RbacV1().Roles("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var roles []*rbacv1.Role
	for i := range roleList.Items {
		roles = append(roles, &roleList.Items[i])
	}

	return roles, nil
}

func RBACSettings(roles []*rbac.Role) {
	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintln(w, "ROLE NAME\tPERMISSIONS")

	for _, role := range roles {
		// Process role to get its name and permissions
		roleName := role.Name
		permissions := GetPermissionsFromRole(role)
		fmt.Fprintf(w, "%s\t%s\n", roleName, permissions)
	}

	w.Flush()
}

// printRoles prints the roles and their permissions in a table format.
