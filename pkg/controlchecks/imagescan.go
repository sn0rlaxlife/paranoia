package controlchecks

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	trivyv1alpha "github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type ReportFilter struct {
	ImageName string
	Labels    map[string]string
}

func init() {
	// Register the trivy operator types with the global scheme
	_ = trivyv1alpha.AddToScheme(scheme.Scheme)
}

func FetchVulnerabilityReports(ctx context.Context, cfg *rest.Config, namespace string) ([]trivyv1alpha.VulnerabilityReport, error) {
	// Create a new client
	c, err := client.New(cfg, client.Options{})
	if err != nil {
		return nil, err
	}

	// List all the VulnerabilityReports in the namespace
	var reportsList trivyv1alpha.VulnerabilityReportList
	if err := c.List(ctx, &reportsList, client.InNamespace(namespace)); err != nil {
		return nil, err
	}

	return reportsList.Items, nil
}

func ScanImages(clientset *kubernetes.Clientset, imageFlag string) error {
	// Check if Docker is Installed
	_, err := exec.LookPath("docker")
	if err != nil {
		return fmt.Errorf("docker is not installed. Please install Docker to scan images")
	}

	// Check if Grype is installed
	_, err = exec.LookPath("grype")
	if err != nil {
		return fmt.Errorf("grype is not installed. Please install Grype to scan images")
	}

	pods, err := clientset.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list pods: %w", err)
	}

	images := make(map[string]struct{})
	for _, pod := range pods.Items {
		for _, container := range pod.Spec.Containers {
			images[container.Image] = struct{}{}
		}
	}

	for image := range images {
		// pull the image
		pullCmd := exec.Command("docker", "pull", image)
		if err := pullCmd.Run(); err != nil {
			return fmt.Errorf("error pulling image %s: %w", image, err)
		}
		// Scan the image with Grype
		scanCmd := exec.Command("grype", image)
		output, err := scanCmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("error scanning image: %w", err)
		}

		// Analyze the output to determine if it meets your vulnerability thresholds
		// This is a placeholder - replace with your actual analysis code
		if strings.Contains(string(output), "HIGH") {
			fmt.Printf("Image %s has high vulnerabilities: %s\n", image, output)
		}
	}

	return nil
}
