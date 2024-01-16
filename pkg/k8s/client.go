// /pkg/kubernetes/client.go

package kubernetes

import (
	"os"
	"path/filepath"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Initialize the kubernetes client
func NewClientSet() (*kubernetes.Clientset, error) {
	var config *rest.Config
	var err error

	// Try to create an in-cluster config
	config, err = rest.InClusterConfig()
	if err != nil {
		// If an in-cluster config can't be created, create an out-of-cluster config
		kubeconfig := filepath.Join(os.Getenv("HOME"), ".kube", "config")
		if envKubeconfig := os.Getenv("KUBECONFIG"); envKubeconfig != "" {
			kubeconfig = envKubeconfig
		}
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			// handle error
			return nil, err
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		// handle error
		return nil, err
	}

	return clientset, nil
}
