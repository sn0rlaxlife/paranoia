package cmd

import (
	watcher "kspm/pkg/k8s"

	"github.com/spf13/cobra"
	kubernetes "k8s.io/client-go/kubernetes"
)

var rootCmd = &cobra.Command{
	Use:   "root",
	Short: "Root command",
	Long:  "This is the root command",
}

func init() {
	rootCmd.AddCommand(watchCmd)
}

func WatchPods(clientset *kubernetes.Clientset) {
	// Implement your logic to watch Kubernetes pods here
	watcher.WatchPods(clientset)

}
