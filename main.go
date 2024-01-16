package main

import (
	"fmt" // Adjust this import to match your project's structure
	"os"

	watcher "kspm/pkg/k8s"

	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// main is the entry point of the program.
func main() {
	// Define the watchCmd variable
	var watchCmd = &cobra.Command{
		Use:   "watch",
		Short: "Start watching Kubernetes resources",
		Long:  `Starts the Kubernetes watcher to monitor resources.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Initialize Kubernetes client
			config, err := rest.InClusterConfig()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating in-cluster config: %v\n", err)
				os.Exit(1)
			}

			clientset, err := kubernetes.NewForConfig(config)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating Kubernetes client: %v\n", err)
				os.Exit(1)
			}

			// Start the Kubernetes watcher
			watcher.WatchPods(clientset)
		},
	} // Replace Command with the actual type of your watch command

	if err := watchCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)

		os.Exit(1)
	}
}
