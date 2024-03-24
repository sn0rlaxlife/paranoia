package entity

import (
	"context"
	"fmt"
	"kspm/pkg/riskposture"
	"log"
	"os"
	"text/tabwriter"

	"github.com/fatih/color"
	v1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Rbac is a struct that represents a Kubernetes RBAC object.
type Rule struct {
	Verbs           []string `json:"verbs"`
	APIGroups       []string `json:"apiGroups"`
	Resources       []string `json:"resources"`
	ResourceNames   []string `json:"resourceNames"`
	NonResourceURLs []string `json:"nonResourceURLs"`
}

type RBACRoleList struct {
	// Name is the name of the RBAC object.
	Name        string // Namespace is the namespace of the RBAC object.
	Namespace   string
	Permissions []string // list of permissions "get/list/watch"
	Resources   []string // list of resources "pods/secrets"
	Rules       []Rule   // list of rules referenced
}

func (r *RBACRoleList) GetRules() ([]string, []string, []Rule) {
	return r.Permissions, r.Resources, r.Rules
}

type RBACRoles []RBACRoleList
type PolicyRule struct {

	// Verbs is a list of Verbs that apply to ALL the ResourceKinds and AttributeRestrictions contained in this rule.
	// Each verb may be one of the following values:
	Verbs []string `json:"verbs"`
	//API Groups is the name that contains the resources
	APIGroups []string `json:"apiGroups"`
	// Resources is a list of resources this rule applies to. ResourceAll represents all resources.
	Resources []string `json:"resources"`
	// ResourceNames is an optional white list of names that the rule applies to. An empty set means that everything is allowed.
	ResourceNames []string `json:"resourceNames"`
	// NonResourceURLs is a set of partial urls that a user should have access to. *s are allowed, but only as the full, final step in the path. "*/" is allowed, but a bare "*" is not. (this means you can't have a single * in the middle of a url).`
	NonResourceURLs []string `json:"nonResourceURLs"`
}

func AnalyzeClusterRoles(clientset *kubernetes.Clientset, clusterRoleName string) error {

	rbacClient := clientset.RbacV1()

	// Fetch cluster roles
	clusterRole, err := rbacClient.ClusterRoles().Get(context.TODO(), clusterRoleName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to fetch cluster role: %v", err)
	}

	// Analyze permissions
	for _, rule := range clusterRole.Rules {
		fmt.Println("Rule:", rule)

		// Resource Access
		fmt.Printf("    -API Groups: %v\n", rule.APIGroups)
		fmt.Printf("    -Resources: %v\n", rule.Resources)

		// Verbs
		fmt.Printf("    -Verbs: %v\n", rule.Verbs)

		// Potential risks
		if HasWildcard(rule.Verbs) {
			fmt.Println("   -Warning: Wildcard verbs detected ****highly privileged****")
		}
		if HasDangerousVerbs(rule.Verbs) {
			fmt.Println("   -Warning: Dangerous verbs detected ****highly privileged****")
		}
	}

	return nil

}

func HasWildcard(verbs []string) bool {
	for _, verb := range verbs {
		if verb == "*" {
			return true
		}
	}
	return false
}

func HasDangerousVerbs(verbs []string) bool {
	dangerousVerbs := []string{"create", "delete", "update", "patch", "bind"}
	for _, verb := range verbs {
		for _, dangerousVerb := range dangerousVerbs {
			if verb == dangerousVerb {
				return true
			}
		}
	}
	return false
}

func PrintExcessPrivileges(excessPrivileges [][]PolicyRule) {
	red := color.New(color.FgRed).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	blue := color.New(color.FgBlue).SprintFunc()

	// Initialize a tabwriter
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	// Print the headers
	fmt.Fprintln(w, "API Group\tVerb\tResource")

	for _, policyRules := range excessPrivileges {
		for _, rule := range policyRules {
			for i := 0; i < len(rule.Verbs) || i < len(rule.Resources) || i < len(rule.APIGroups); i++ {
				var verb, resource, apiGroup string
				if i < len(rule.Verbs) {
					verb = red(rule.Verbs[i])
				}
				if i < len(rule.Resources) {
					resource = green(rule.Resources[i])
				}
				if i < len(rule.APIGroups) {
					apiGroup = blue(rule.APIGroups[i])
				}
				// Print the data
				fmt.Fprintf(w, "%s\t%s\t%s\n", apiGroup, verb, resource)
			}
		}
	}
	// Flush the writer to print the output
	w.Flush()
}

// Newrole list creates a role list from the kubernetes RBAC
func NewRBACRoleList(roles []v1.Role) (RBACRoles, [][]string) {
	var list RBACRoles
	var allFlaggedPermissions [][]string
	for _, role := range roles {
		// Convert "k8s.io/api/rbac/v1".Role to PolicyRule
		policyRule := ConvertRoleToPolicyRule(role)

		// Assign the 4 return values from extractPermissionsAndResources to 4 variables
		permissions, resources, flaggedPermissions, err := ExtractPermissionsAndResources(policyRule)
		if err != nil {
			log.Printf("Error extracting permissions and resources: %v", err)
			continue
		}
		list = append(list, RBACRoleList{
			Name:        role.Name,
			Namespace:   role.Namespace,
			Permissions: permissions,
			Resources:   resources,
		})
		allFlaggedPermissions = append(allFlaggedPermissions, flaggedPermissions)
	}
	return list, allFlaggedPermissions
}

func NewRBACClusterRoleList(roles []v1.ClusterRole) (RBACRoles, [][]string) {
	var list RBACRoles
	var allFlaggedPermissions [][]string
	for _, role := range roles {
		policyRules := ConvertClusterRoleToPolicyRule(role)
		// Convert "k8s.io/api/rbac/v1".Role to PolicyRule
		for _, policyRule := range policyRules {
			// Convert v1.PolicyRule to PolicyRule
			convertedPolicyRule := PolicyRule{
				Verbs:         policyRule.Verbs,
				APIGroups:     policyRule.APIGroups,
				Resources:     policyRule.Resources,
				ResourceNames: policyRule.ResourceNames,
			}

			// Assign the 4 return values from extractPermissionsAndResources to 4 variables
			permissions, resources, _, err := ExtractPermissionsAndResources(convertedPolicyRule) // Removed flaggedPermissions
			if err != nil {
				log.Printf("Error extracting permissions and resources: %v", err)
				continue
			}
			list = append(list, RBACRoleList{
				Name:        role.Name,
				Namespace:   "",
				Permissions: permissions,
				Resources:   resources,
			})
			// Removed clusterRoles and allFlaggedPermissions as they were not used
		}
	}
	return list, allFlaggedPermissions
}

func ConvertClusterRoleToPolicyRule(role v1.ClusterRole) []v1.PolicyRule {
	// Assuming that the PolicyRules in a ClusterRole are what you want
	return role.Rules
}

func ConvertRoleToPolicyRule(role v1.Role) PolicyRule {
	policyRule := PolicyRule{
		Verbs:         role.Rules[0].Verbs,
		APIGroups:     role.Rules[0].APIGroups,
		Resources:     role.Rules[0].Resources,
		ResourceNames: role.Rules[0].ResourceNames,
	}
	return policyRule
}

func ConvertPolicyRules(input []v1.PolicyRule) []PolicyRule {
	var output []PolicyRule
	for _, policyRule := range input {
		// Assuming entity.PolicyRule and v1.PolicyRule have similar fields
		entityPolicyRule := PolicyRule{
			Verbs:           policyRule.Verbs,
			APIGroups:       policyRule.APIGroups,
			Resources:       policyRule.Resources,
			ResourceNames:   policyRule.ResourceNames,
			NonResourceURLs: policyRule.NonResourceURLs,
		}
		output = append(output, entityPolicyRule)
	}
	return output
}

// extractPermissionsAndResources extracts the permissions and resources from a kubernetes RBAC role
func ExtractPermissionsAndResources(rule PolicyRule) ([]string, []string, []string, error) {
	var permissions []string
	var resources []string
	var flaggedPermissions []string

	for _, verb := range rule.Verbs {
		permissions = append(permissions, verb)
		if verb == "create" || verb == "delete" || verb == "update" {
			flaggedPermissions = append(flaggedPermissions, verb)
		}
	}

	resources = rule.Resources

	return permissions, resources, flaggedPermissions, nil
}

func ConvertRoleToFunction(role RBACRoleList, roleList [][]PolicyRule) []riskposture.Function {
	var functionscalc []riskposture.Function
	// Extract the permissions from the role

	//loop over outer slice to access RBAC Roles Listings
	for _, roles := range roleList {
		// loop over inner slice to access individual roles
		for _, r := range roles {
			permissions, resources, flaggedPermissions, err := ExtractPermissionsAndResources(r)
			if err != nil {
				log.Printf("Error extracting permissions and resources: %v", err)
				continue
			}

			fmt.Println(resources, flaggedPermissions, permissions)
			// Calculate the risk level as the number of permissions
			riskLevel := len(permissions)

			function := riskposture.Function{
				Name:      role.Name,
				RiskLevel: riskLevel,
			}
			functionscalc = append(functionscalc, function)
		}
	}
	// Return the slice of functions
	return functionscalc
}
