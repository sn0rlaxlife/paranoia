package kubernetes

import (
	"fmt"

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
				fmt.Printf("New Pod Added: %s in namespace %s\n", pod.Name, pod.Namespace)
				CheckPodSecurity(pod)
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
}
