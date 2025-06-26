package k8s

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/fatih/color"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// SecurityEvent represents a detected security issue
type SecurityEvent struct {
	Timestamp   time.Time
	Severity    string // "INFO", "WARNING", "CRITICAL"
	ResourceType string
	ResourceName string
	Namespace    string
	Message      string
}

// SecurityEventHandler handles security events (implement based on your needs)
type SecurityEventHandler interface {
	HandleEvent(event SecurityEvent)
}

// ConsoleSecurityEventHandler outputs security events to the console
type ConsoleSecurityEventHandler struct{}

func (h ConsoleSecurityEventHandler) HandleEvent(event SecurityEvent) {
	var output func(format string, a ...interface{})
	
	switch event.Severity {
	case "CRITICAL":
		output = color.New(color.FgHiRed, color.Bold).PrintfFunc()
	case "WARNING":
		output = color.New(color.FgHiYellow).PrintfFunc()
	case "INFO":
		output = color.New(color.FgHiCyan).PrintfFunc()
	default:
		// Directly use fmt.Printf instead of assigning it to output
		fmt.Printf("[%s][%s] %s/%s in namespace %s: %s\n", 
			event.Timestamp.Format(time.RFC3339),
			event.Severity,
			event.ResourceType,
			event.ResourceName,
			event.Namespace,
			event.Message,
		)
		return
	}
	
	output("[%s][%s] %s/%s in namespace %s: %s\n", 
		event.Timestamp.Format(time.RFC3339),
		event.Severity,
		event.ResourceType,
		event.ResourceName,
		event.Namespace,
		event.Message,
	)
}

var eventHandler SecurityEventHandler = ConsoleSecurityEventHandler{}

// SetSecurityEventHandler sets the handler for security events
func SetSecurityEventHandler(handler SecurityEventHandler) {
	eventHandler = handler
}

// reportSecurityEvent creates and processes a security event
func reportSecurityEvent(severity, resourceType, resourceName, namespace, message string) {
	event := SecurityEvent{
		Timestamp:    time.Now(),
		Severity:     severity,
		ResourceType: resourceType,
		ResourceName: resourceName,
		Namespace:    namespace,
		Message:      message,
	}
	
	eventHandler.HandleEvent(event)
}

// checkRole checks if a Role has excessive permissions
func checkRole(role rbacv1.Role) bool {
	// Check for dangerous permissions
	for _, rule := range role.Rules {
		// Check for wildcard resources
		for _, resource := range rule.Resources {
			if resource == "*" {
				reportSecurityEvent("WARNING", "Role", role.Name, role.Namespace, 
					"Role has wildcard resource permissions")
				return false
			}
		}
		
		// Check for wildcard verbs
		if contains(rule.Verbs, "*") {
			reportSecurityEvent("WARNING", "Role", role.Name, role.Namespace, 
				"Role has wildcard verb permissions")
			return false
		}
	}
	
	return true
}

// WatchClusterRoles monitors ClusterRole resources
func WatchClusterRoles(clientset *kubernetes.Clientset) (cache.Controller, chan struct{}) {
	watchlist := cache.NewListWatchFromClient(
		clientset.RbacV1().RESTClient(),
		"clusterroles",
		metav1.NamespaceAll,
		fields.Everything(),
	)

	_, controller := cache.NewInformer(
		watchlist,
		&rbacv1.ClusterRole{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				role := obj.(*rbacv1.ClusterRole)
				reportSecurityEvent("INFO", "ClusterRole", role.Name, "cluster-wide", 
					"ClusterRole added")
				CheckClusterRoleSecurity(role)
			},
			UpdateFunc: func(_, newObj interface{}) {
				role := newObj.(*rbacv1.ClusterRole)
				reportSecurityEvent("INFO", "ClusterRole", role.Name, "cluster-wide", 
					"ClusterRole updated")
				CheckClusterRoleSecurity(role)
			},
		},
	)

	stop := make(chan struct{})
	go controller.Run(stop)
	
	return controller, stop
}

// WatchDeployments monitors Deployment resources
func WatchDeployments(clientset *kubernetes.Clientset) (cache.Controller, chan struct{}) {
	watchlist := cache.NewListWatchFromClient(
		clientset.AppsV1().RESTClient(),
		"deployments",
		metav1.NamespaceAll,
		fields.Everything(),
	)

	_, controller := cache.NewInformer(
		watchlist,
		&appsv1.Deployment{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				deployment := obj.(*appsv1.Deployment)
				reportSecurityEvent("INFO", "Deployment", deployment.Name, deployment.Namespace, 
					"Deployment added")
				CheckDeploymentSecurity(deployment)
			},
			UpdateFunc: func(_, newObj interface{}) {
				deployment := newObj.(*appsv1.Deployment)
				reportSecurityEvent("INFO", "Deployment", deployment.Name, deployment.Namespace, 
					"Deployment updated")
				CheckDeploymentSecurity(deployment)
			},
		},
	)

	stop := make(chan struct{})
	go controller.Run(stop)
	
	return controller, stop
}

// WatchSecrets monitors Secret resources
func WatchSecrets(clientset *kubernetes.Clientset) (cache.Controller, chan struct{}) {
	watchlist := cache.NewListWatchFromClient(
		clientset.CoreV1().RESTClient(),
		"secrets",
		metav1.NamespaceAll,
		fields.Everything(),
	)

	_, controller := cache.NewInformer(
		watchlist,
		&corev1.Secret{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				secret := obj.(*corev1.Secret)
				reportSecurityEvent("INFO", "Secret", secret.Name, secret.Namespace, 
					fmt.Sprintf("Secret added (type: %s)", secret.Type))
				CheckSecretSecurity(secret)
			},
			UpdateFunc: func(_, newObj interface{}) {
				secret := newObj.(*corev1.Secret)
				reportSecurityEvent("INFO", "Secret", secret.Name, secret.Namespace, 
					fmt.Sprintf("Secret updated (type: %s)", secret.Type))
				CheckSecretSecurity(secret)
			},
		},
	)

	stop := make(chan struct{})
	go controller.Run(stop)
	
	return controller, stop
}

// WatchPods sets up a watch on Pod resources in the cluster
func WatchPods(clientset *kubernetes.Clientset) (cache.Controller, chan struct{}) {
	watchlist := cache.NewListWatchFromClient(
		clientset.CoreV1().RESTClient(),
		"pods",
		metav1.NamespaceAll,
		fields.Everything(),
	)

	_, controller := cache.NewInformer(
		watchlist,
		&corev1.Pod{},
		0, // Duration is set to 0 for no resync
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				pod := obj.(*corev1.Pod)
				info := color.New(color.FgHiGreen).PrintfFunc()
				info("[+]Pod Added: %s in namespace %s\n", pod.Name, pod.Namespace)
				CheckPodSecurity(pod)
			},
			DeleteFunc: func(obj interface{}) {
				pod := obj.(*corev1.Pod)
				fmt.Printf("Pod Deleted: %s in namespace %s\n", pod.Name, pod.Namespace)
			},
			UpdateFunc: func(_, newObj interface{}) {
				newPod := newObj.(*corev1.Pod)
				fmt.Printf("Pod Updated: %s in namespace %s\n", newPod.Name, newPod.Namespace)
				CheckPodSecurity(newPod)
			},
		},
	)

	stop := make(chan struct{})
	go controller.Run(stop)
	
	return controller, stop
}

// CheckPodSecurity performs security checks on the provided Pod
func CheckPodSecurity(pod *corev1.Pod) {
	// Example security check: Check for privileged containers
	for _, container := range pod.Spec.Containers {
		if container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
			warning := color.New(color.FgHiRed).PrintfFunc()
			warning("Warning: Pod %s in namespace %s has a privileged container\n", pod.Name, pod.Namespace)
		}
	}
	// Example security check: Check for insecure capabilities
	// Implement more security checks here
	for _, container := range pod.Spec.Containers {
		if container.SecurityContext != nil && container.SecurityContext.Capabilities != nil {
			for _, cap := range container.SecurityContext.Capabilities.Add {
				if cap == "ALL" || cap == "NET_ADMIN" || cap == "SYS_ADMIN" {
					warning := color.New(color.FgHiRed).PrintfFunc()
					warning("Warning: Pod %s in namespace %s has a container with insecure capabilities\n", pod.Name, pod.Namespace)
				}
			}
		}
	}
	if pod.Spec.HostNetwork {
		warning := color.New(color.FgHiRed).PrintfFunc()
		warning("Warning: Pod %s in namespace %s has host network access\n", pod.Name, pod.Namespace)
	}

	// New security checks
	
	// Check for hostPID/hostIPC use
	if pod.Spec.HostPID {
		reportSecurityEvent("CRITICAL", "Pod", pod.Name, pod.Namespace, 
			"Pod has hostPID access which can expose host processes")
	}
	
	if pod.Spec.HostIPC {
		reportSecurityEvent("CRITICAL", "Pod", pod.Name, pod.Namespace, 
			"Pod has hostIPC access which can expose host IPC namespace")
	}
	
	// Check for host volume mounts
	for _, volume := range pod.Spec.Volumes {
		if volume.HostPath != nil {
			reportSecurityEvent("WARNING", "Pod", pod.Name, pod.Namespace, 
				fmt.Sprintf("Pod mounts host path: %s", volume.HostPath.Path))
			
			// Check for sensitive paths
			sensitivePaths := []string{"/etc", "/var/run/docker.sock", "/proc", "/var/log"}
			for _, sensitive := range sensitivePaths {
				if strings.HasPrefix(volume.HostPath.Path, sensitive) {
					reportSecurityEvent("CRITICAL", "Pod", pod.Name, pod.Namespace, 
						fmt.Sprintf("Pod mounts sensitive host path: %s", volume.HostPath.Path))
				}
			}
		}
	}
	
	// Check Security Context
	if pod.Spec.SecurityContext == nil {
		reportSecurityEvent("INFO", "Pod", pod.Name, pod.Namespace, 
			"Pod has no security context defined")
	} else {
		// Check for allowPrivilegeEscalation
		for _, container := range pod.Spec.Containers {
			if container.SecurityContext != nil && 
			   container.SecurityContext.AllowPrivilegeEscalation != nil && 
			   *container.SecurityContext.AllowPrivilegeEscalation {
				reportSecurityEvent("WARNING", "Pod", pod.Name, pod.Namespace, 
					fmt.Sprintf("Container %s allows privilege escalation", container.Name))
			}
			
			// Check for running as root
			if container.SecurityContext == nil || 
			   container.SecurityContext.RunAsNonRoot == nil || 
			   !*container.SecurityContext.RunAsNonRoot {
				reportSecurityEvent("INFO", "Pod", pod.Name, pod.Namespace, 
					fmt.Sprintf("Container %s may run as root", container.Name))
			}
			
			// Check for read-only root filesystem
			if container.SecurityContext == nil || 
			   container.SecurityContext.ReadOnlyRootFilesystem == nil || 
			   !*container.SecurityContext.ReadOnlyRootFilesystem {
				reportSecurityEvent("INFO", "Pod", pod.Name, pod.Namespace, 
					fmt.Sprintf("Container %s has writable root filesystem", container.Name))
			}
		}
	}
	
	// Check for latest tag
	for _, container := range pod.Spec.Containers {
		if strings.HasSuffix(container.Image, ":latest") || !strings.Contains(container.Image, ":") {
			reportSecurityEvent("WARNING", "Pod", pod.Name, pod.Namespace, 
				fmt.Sprintf("Container %s uses 'latest' tag which is mutable", container.Name))
		}
	}
}

var imageNameRegex = regexp.MustCompile(`(?:([^/]+)/)?([^@:]+)(?:[@:](.+))?`)

func CheckServiceAccount(pod *corev1.Pod, clientset *kubernetes.Clientset) {
	serviceAccount, err := clientset.CoreV1().ServiceAccounts(pod.Namespace).Get(context.TODO(), pod.Spec.ServiceAccountName, metav1.GetOptions{})
	if err != nil {
		fmt.Printf("Error getting service account: %v\n", err)
		return
	}
	for _, secret := range serviceAccount.Secrets {
		secret, err := clientset.CoreV1().Secrets(pod.Namespace).Get(context.TODO(), secret.Name, metav1.GetOptions{})
		if err != nil {
			fmt.Printf("Error getting secret: %v\n", err)
			continue
		}
		if secret.Type == corev1.SecretTypeServiceAccountToken {
			warning := color.New(color.FgHiRed).PrintfFunc()
			warning("Warning: Pod %s in namespace %s is using a service account token\n", pod.Name, pod.Namespace)
		}
	}

}

func sendImagesToGuac(images []string) error {
	for _, image := range images {
		// Remove the 'registry.k8s.io/' prefix from the image name
		matches := imageNameRegex.FindStringSubmatch(image)
		if matches == nil {
			return fmt.Errorf("failed to parse image name %s", image)
		}
		imageNameAndTag := fmt.Sprintf("%s:%s", matches[2], matches[3])
		// Pull the image with Docker
		fmt.Printf("Pulling image %s\n", imageNameAndTag)
		pullCmd := exec.Command("docker", "pull", imageNameAndTag)
		pullOutput, err := pullCmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to pull image %s: %s, error: %w", imageNameAndTag, string(pullOutput), err)
		}

		// Get the home directory
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}

		// Scan the image with Trivy in a Docker container
		scanCmd := exec.Command("docker", "run", "--rm", "-v", "/var/run/docker.sock:/var/run/docker.sock", "-v", fmt.Sprintf("%s/Library/Caches:/root/.cache/", homeDir), "aquasec/trivy", "image", imageNameAndTag)
		scanOutput, err := scanCmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to scan image %s: %s, error: %w", imageNameAndTag, string(scanOutput), err)
		}

		// Print the scan output
		fmt.Printf("Output for image %s: %s\n", imageNameAndTag, string(scanOutput))
	}

	return nil
}

// CheckDeploymentSecurity performs security checks on Deployments
func CheckDeploymentSecurity(deployment *appsv1.Deployment) {
    // Create a new Pod object from the PodTemplateSpec
    pod := &corev1.Pod{
        Spec: deployment.Spec.Template.Spec,
        ObjectMeta: metav1.ObjectMeta{
            Name:      deployment.Name,
            Namespace: deployment.Namespace,
            Labels:    deployment.Spec.Template.Labels,
        },
    }

    // Check if deployment has pod security context
    if deployment.Spec.Template.Spec.SecurityContext == nil {
        reportSecurityEvent("INFO", "Deployment", deployment.Name, deployment.Namespace,
            "Deployment has no pod security context defined")
    }
    
    // Check for resource limits/requests
    for _, container := range deployment.Spec.Template.Spec.Containers {
        if container.Resources.Limits == nil || len(container.Resources.Limits) == 0 {
            reportSecurityEvent("WARNING", "Deployment", deployment.Name, deployment.Namespace,
                fmt.Sprintf("Container %s has no resource limits defined", container.Name))
        }
        
        if container.Resources.Requests == nil || len(container.Resources.Requests) == 0 {
            reportSecurityEvent("INFO", "Deployment", deployment.Name, deployment.Namespace,
                fmt.Sprintf("Container %s has no resource requests defined", container.Name))
        }
    }
    
    // Check pod template for security issues
    CheckPodSecurity(pod)
}

// CheckClusterRoleSecurity examines a ClusterRole for security issues
func CheckClusterRoleSecurity(role *rbacv1.ClusterRole) {
	dangerousVerbs := []string{"create", "delete", "update", "patch"}
	dangerousResources := []string{"secrets", "roles", "rolebindings", "clusterroles", "clusterrolebindings"}
	
	for _, rule := range role.Rules {
		// Check for wildcard permissions
		if contains(rule.Resources, "*") {
			reportSecurityEvent("CRITICAL", "ClusterRole", role.Name, "cluster-wide",
				"ClusterRole has wildcard resource permissions")
		}
		
		if contains(rule.Verbs, "*") {
			reportSecurityEvent("WARNING", "ClusterRole", role.Name, "cluster-wide",
				"ClusterRole has wildcard verb permissions")
		}
		
		// Check for dangerous permissions
		for _, resource := range rule.Resources {
			if contains(dangerousResources, resource) {
				for _, verb := range rule.Verbs {
					if contains(dangerousVerbs, verb) {
						reportSecurityEvent("WARNING", "ClusterRole", role.Name, "cluster-wide",
							fmt.Sprintf("ClusterRole has sensitive permission: %s %s", verb, resource))
					}
				}
			}
		}
	}
}

// CheckSecretSecurity examines secrets for security issues
func CheckSecretSecurity(secret *corev1.Secret) {
	// Check for default service account tokens
	if secret.Type == corev1.SecretTypeServiceAccountToken && 
	   strings.HasPrefix(secret.Name, "default-token-") {
		reportSecurityEvent("INFO", "Secret", secret.Name, secret.Namespace,
			"Default service account token created")
	}
	
	// Check for potentially sensitive data in generic secrets
	if secret.Type == corev1.SecretTypeOpaque {
		sensitiveKeys := []string{"password", "token", "key", "secret", "credential", "cert"}
		for key := range secret.Data {
			keyLower := strings.ToLower(key)
			for _, sensitiveKey := range sensitiveKeys {
				if strings.Contains(keyLower, sensitiveKey) {
					reportSecurityEvent("INFO", "Secret", secret.Name, secret.Namespace,
						fmt.Sprintf("Secret contains potentially sensitive key: %s", key))
					break
				}
			}
		}
	}
}

// StartKubernetesWatchers initializes all watchers
func StartKubernetesWatchers(clientset *kubernetes.Clientset, options map[string]bool) []chan struct{} {
    var stopChannels []chan struct{}
    
	// Add debugging
	fmt.Println("Debug: StartKubernetesWatchers called with options:", options)

	// Start watchers based on options
    if options["pods"] {
        _, stopCh := WatchPods(clientset)
        stopChannels = append(stopChannels, stopCh)
		color.Green("Pod watcher started")
    }
    
    if options["deployments"] {
        _, stopCh := WatchDeployments(clientset)
        stopChannels = append(stopChannels, stopCh)
		color.Green("Deployment watcher started")
    }
    
    if options["secrets"] {
        _, stopCh := WatchSecrets(clientset)
        stopChannels = append(stopChannels, stopCh)
		color.Green("Secret watcher started")
    }
    
    if options["clusterRoles"] {
		fmt.Println("Debug: Starting ClusterRole watcher")
        _, stopCh := WatchClusterRoles(clientset)
        stopChannels = append(stopChannels, stopCh)
		color.Green("ClusterRole watcher started")
    }
    
	fmt.Printf("Debug: Started %d watchers\n", len(stopChannels))
    return stopChannels
}

// Helper function to check if a string slice contains a value
func contains(slice []string, value string) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
}
