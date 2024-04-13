package kubernetes

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"

	"github.com/fatih/color"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

func checkRole(role rbacv1.Role) bool {
	// Implement your control requirements here
	return true
}

// WatchPods sets up a watch on Pod resources in the cluster
func WatchPods(clientset *kubernetes.Clientset) {
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
	defer close(stop)
	go controller.Run(stop)

	// Block forever
	select {}
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
