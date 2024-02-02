package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"kspm/pkg/entity"
	watcher "kspm/pkg/k8s"

	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var kubeconfig string

var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Start watching Kubernetes resources",
	Long:  `Starts the Kubernetes watcher to monitor resources.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Initialize Kubernetes client
		if kubeconfig == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error getting user home directory: %v\n", err)
				os.Exit(1)
			}
			kubeconfig = filepath.Join(home, ".kube", "config")
		}
		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating in-cluster config: %v\n", err)
			os.Exit(1)
		}

		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating Kubernetes client: %v\n", err)
			os.Exit(1)
		}
		// Start the watcher function command
		watcher.WatchPods(clientset)
	},
}
var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Run control checks",
	Long:  `Runs the control checks against the cluster.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Initialize Kubernetes client
		if kubeconfig == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error getting user home directory: %v\n", err)
				os.Exit(1)
			}
			kubeconfig = filepath.Join(home, ".kube", "config")
		}
		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating in-cluster config: %v\n", err)
			os.Exit(1)
		}
		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating Kubernetes client: %v\n", err)
			os.Exit(1)
		}
		// Start the entity Kubernetes watcher
		entity.RBACRoles(clientset)
	},
}

func init() {
	rootCmd.AddCommand(watchCmd)
	rootCmd.AddCommand(checkCmd)
	// Here you will define your flags and configuration settings.
	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// rootCmd.PersistentFlags().String("foo", "", "A help for foo")

}
