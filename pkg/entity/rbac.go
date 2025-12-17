package entity

import (
	"context"
	"fmt"
	"kspm/pkg/riskposture"
	"log"
	"os"
	"strings"
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

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func AnalyzeClusterRoles(clientset *kubernetes.Clientset, clusterRoleName string) ([]string, []riskposture.Signal, error) {
	rbacClient := clientset.RbacV1()

	cr, err := rbacClient.ClusterRoles().Get(context.TODO(), clusterRoleName, metav1.GetOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch cluster role %q: %w", clusterRoleName, err)
	}

	var findings []string
	var signals []riskposture.Signal

	for _, rule := range cr.Rules {
		// --- Wildcard verbs ---
		if HasWildcard(rule.Verbs) {
			findings = append(findings,
				fmt.Sprintf("[HIGH] ClusterRole/%s: wildcard verbs '*' detected (highly privileged)", cr.Name),
			)
			signals = append(signals, riskposture.Signal{
				Name:     "WildcardRBAC",
				Severity: "HIGH",
				Weight:   25,
			})
		}

		// --- Dangerous verbs ---
		if HasDangerousVerbs(rule.Verbs) {
			findings = append(findings,
				fmt.Sprintf("[MEDIUM] ClusterRole/%s: dangerous verbs detected (%v)", cr.Name, rule.Verbs),
			)
			signals = append(signals, riskposture.Signal{
				Name:     "DangerousRBACVerbs",
				Severity: "MEDIUM",
				Weight:   15,
			})
		}

		// --- Wildcard resources ---
		if HasWildcard(rule.Resources) {
			findings = append(findings,
				fmt.Sprintf("[HIGH] ClusterRole/%s: wildcard resources '*' detected", cr.Name),
			)
			signals = append(signals, riskposture.Signal{
				Name:     "WildcardRBACResources",
				Severity: "HIGH",
				Weight:   25,
			})
		}

		// --- Secrets access ---
		if contains(rule.Resources, "secrets") && (contains(rule.Verbs, "get") || contains(rule.Verbs, "list") || contains(rule.Verbs, "watch")) {
			findings = append(findings,
				fmt.Sprintf("[HIGH] ClusterRole/%s: read access to secrets detected (verbs=%v)", cr.Name, rule.Verbs),
			)
			signals = append(signals, riskposture.Signal{
				Name:     "SecretsAccess",
				Severity: "HIGH",
				Weight:   20,
			})
		}

		// --- Impersonate / escalation-ish verbs (nice add) ---
		if contains(rule.Verbs, "impersonate") || contains(rule.Verbs, "bind") || contains(rule.Verbs, "escalate") {
			findings = append(findings,
				fmt.Sprintf("[HIGH] ClusterRole/%s: escalation verbs detected (impersonate/bind/escalate)", cr.Name),
			)
			signals = append(signals, riskposture.Signal{
				Name:     "RBACEscalationVerbs",
				Severity: "HIGH",
				Weight:   25,
			})
		}
	}

	return findings, signals, nil
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
	dangerous := map[string]struct{}{
		"create": {}, "delete": {}, "update": {}, "patch": {},
		"bind": {}, "escalate": {}, "impersonate": {},
	}
	for _, v := range verbs {
		if _, ok := dangerous[v]; ok {
			return true
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
			verbs := strings.Join(rule.Verbs, ", ")
			resources := strings.Join(rule.Resources, ", ")
			apiGroups := strings.Join(rule.APIGroups, ", ")

			// Color the strings
			verb := red(verbs)
			resource := green(resources)
			apiGroup := blue(apiGroups)
			// Print the data
			fmt.Fprintf(w, "%s\t%s\t%s\n", apiGroup, verb, resource)
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

func ConvertRoleToSignals(
	role RBACRoleList,
	roleList [][]PolicyRule,
) []riskposture.Signal {

	var signals []riskposture.Signal

	for _, rules := range roleList {
		for _, r := range rules {
			perms, resources, flagged, err := ExtractPermissionsAndResources(r)
			if err != nil {
				log.Printf("RBAC extract error: %v", err)
				continue
			}

			// --- CRITICAL: cluster-admin equivalent ---
			if role.Name == "cluster-admin" {
				signals = append(signals, riskposture.Signal{
					Name:     "ClusterAdminBinding",
					Severity: "CRITICAL",
					Weight:   40,
				})
				continue
			}

			// --- HIGH: wildcard RBAC ---
			if HasWildcard(perms) || HasWildcard(resources) {
				signals = append(signals, riskposture.Signal{
					Name:     "WildcardRBAC",
					Severity: "HIGH",
					Weight:   25,
				})
			}

			// --- HIGH: secrets access ---
			if contains(resources, "secrets") {
				signals = append(signals, riskposture.Signal{
					Name:     "SecretsAccess",
					Severity: "HIGH",
					Weight:   20,
				})
			}

			// --- MEDIUM: exec / port-forward ---
			if contains(perms, "pods/exec") || contains(perms, "pods/portforward") {
				signals = append(signals, riskposture.Signal{
					Name:     "PodExecAccess",
					Severity: "MEDIUM",
					Weight:   15,
				})
			}

			// --- INFO: noisy RBAC ---
			if len(flagged) > 0 {
				signals = append(signals, riskposture.Signal{
					Name:     "SuspiciousRBACPattern",
					Severity: "INFO",
					Weight:   5,
				})
			}
		}
	}

	return signals
}
