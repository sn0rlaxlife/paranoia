package cmd

import (
	"fmt"
	"os"

	watcher "kspm/pkg/k8s"

	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Start watching Kubernetes resources",
	Long:  `Starts the Kubernetes watcher to monitor resources.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Initialize Kubernetes client
		kubeconfig := "~/.kube/config"
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

		// Start the Kubernetes watcher
		watcher.WatchPods(clientset)
	},
}

func init() {
	rootCmd.AddCommand(watchCmd)
	// Here you will define your flags and configuration settings.
	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// rootCmd.PersistentFlags().String("foo", "", "A help for foo")

}
