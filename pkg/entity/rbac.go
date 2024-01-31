package entity

import v1 "k8s.io/api/rbac/v1"

// Rbac is a struct that represents a Kubernetes RBAC object.
type RBACRoleList struct {
	// Name is the name of the RBAC object.
	Name        string // Namespace is the namespace of the RBAC object.
	Namespace   string
	Permissions []string // list of permissions "get/list/watch"
	Resources   []string // list of resources "pods/secrets"
}

type RBACRoles []RBACRoleList

// Newrole list creates a role list from the kubernetes RBAC
func NewRBACRoleList(roles []v1.Role) RBACRoles {
	var list RBACRoles
	for _, role := range roles {
		permissions, resources := extractPermissionsAndResources(role)
		list = append(list, RBACRoleList{
			Name:        role.Name,
			Namespace:   role.Namespace,
			Permissions: permissions,
			Resources:   resources,
		})
	}
	return list
}

// extractPermissionsAndResources extracts the permissions and resources from a kubernetes RBAC role
func extractPermissionsAndResources(role v1.Role) (permissions []string, resources []string) {
	for _, rule := range role.Rules {
		for _, verb := range rule.Verbs {
			permissions = append(permissions, verb)
		}
		for _, resource := range rule.Resources {
			resources = append(resources, resource)
		}
	}

	return permissions, resources
}
