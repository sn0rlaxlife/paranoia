package entity

import (
	"context"

	v1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// DeploymentList is a list of Kubernetes deployments.
type DeploymentList []Deployment

// Deployment is a struct that represents a Kubernetes deployment.
type Deployment struct {
	// Name is the name of the deployment.
	Name string
	// Namespace is the namespace of the deployment.
	Namespace string
	// Replicas is the number of replicas for the deployment.
	Replicas int32
	// Labels is a map of labels for the deployment.
	Labels map[string]string
}

// Add a global variable to count the number of violations
// NewDeploymentList creates a deployment list from the Kubernetes deployments.
func NewDeploymentList(deployments *v1.DeploymentList) (DeploymentList, int) {
	var list DeploymentList
	violationCount := 0 // Add a global variable to count the number of violations
	for _, deployment := range deployments.Items {
		if len(deployment.Labels) == 0 {
			violationCount++
		}
		list = append(list, Deployment{
			Name:      deployment.Name,
			Namespace: deployment.Namespace,
			Replicas:  *deployment.Spec.Replicas,
			Labels:    deployment.Labels,
		})
	}
	return list, violationCount // Remove the (string) conversion from the violationCount variable
}

// GetDeploymentList returns a list of deployments from the Kubernetes client.
func GetDeploymentList(clientset kubernetes.Interface) (*v1.DeploymentList, error) {
	deployments, err := clientset.AppsV1().Deployments("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return deployments, nil
}
