package main

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

// setupFakeClientset creates a fake Kubernetes clientset with test data
func setupFakeClientset() kubernetes.Interface {
	// Create fake objects for testing
	testPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
		},
	}

	testNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-node",
		},
	}

	testClusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "system:auth-delegator",
		},
	}

	return fake.NewSimpleClientset(testPod, testNode, testClusterRole)
}

func TestInitClient(t *testing.T) {
	// Test that initClient returns error when no kubeconfig is available
	_, err := initClient()
	// We expect an error in test environment without cluster
	assert.Error(t, err)
}

func TestSetupFakeClientset(t *testing.T) {
	// Test that fake clientset is created successfully
	clientset := setupFakeClientset()
	assert.NotNil(t, clientset)

	// Verify test data exists
	pods, err := clientset.CoreV1().Pods("default").List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	assert.Len(t, pods.Items, 1)
	assert.Equal(t, "test-pod", pods.Items[0].Name)

	nodes, err := clientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	assert.Len(t, nodes.Items, 1)

	clusterRoles, err := clientset.RbacV1().ClusterRoles().List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	assert.Len(t, clusterRoles.Items, 1)
}

func TestCreateWatchCmd(t *testing.T) {
	cmd := createWatchCmd()

	assert.NotNil(t, cmd)
	assert.Equal(t, "watch", cmd.Use)
	assert.Equal(t, "Start watching Kubernetes resources", cmd.Short)

	// Test flags exist
	watchFlag := cmd.Flags().Lookup("watch")
	assert.NotNil(t, watchFlag)
	assert.Equal(t, "bool", watchFlag.Value.Type())
}

func TestCreateCheckCmd(t *testing.T) {
	cmd := createCheckCmd()

	assert.NotNil(t, cmd)
	assert.Equal(t, "check", cmd.Use)
	assert.Equal(t, "Run control checks", cmd.Short)

	// Test flags exist
	//checkFlag := cmd.Flags().Lookup("check")
	//assert.NotNil(t, checkFlag)
	//assert.Equal(t, "bool", checkFlag.Value.Type())
}

func TestCreateDeploymentCmd(t *testing.T) {
	cmd := createDeploymentCmd()

	assert.NotNil(t, cmd)
	assert.Equal(t, "deployment", cmd.Use)
	assert.Equal(t, "Run deployment checks", cmd.Short)

	// Test flags exist
	deploymentFlag := cmd.Flags().Lookup("deployment")
	assert.NotNil(t, deploymentFlag)
}

func TestCreateRbacCmd(t *testing.T) {
	cmd := createRbacCmd()

	assert.NotNil(t, cmd)
	assert.Equal(t, "rbac", cmd.Use)
	assert.Equal(t, "Run RBAC Checks", cmd.Short)

	// Test flags exist
	rbacFlag := cmd.Flags().Lookup("rbac")
	assert.NotNil(t, rbacFlag)
}

func TestReportCmd(t *testing.T) {
	cmd := reportCmd()

	assert.NotNil(t, cmd)
	assert.Equal(t, "report", cmd.Use)
	assert.Equal(t, "Scan images for vulnerabilities", cmd.Short)

	// Test flags exist
	assert.NotNil(t, cmd.Flags().Lookup("namespace"))
	assert.NotNil(t, cmd.Flags().Lookup("kubeconfig"))
}

func TestReportHTMLCmd(t *testing.T) {
	cmd := reportHTMLCmd()

	assert.NotNil(t, cmd)
	assert.Equal(t, "report-html", cmd.Use)
	assert.Equal(t, "Generate comprehensive HTML security report of all findings in the cluster", cmd.Short)

	// Test flags exist
	assert.NotNil(t, cmd.Flags().Lookup("output"))
	assert.NotNil(t, cmd.Flags().Lookup("kubeconfig"))
	assert.NotNil(t, cmd.Flags().Lookup("namespace"))
	assert.NotNil(t, cmd.Flags().Lookup("port"))
}

func TestRootCommand(t *testing.T) {
	assert.NotNil(t, rootCmd)
	assert.Equal(t, "paranoia", rootCmd.Use)
	assert.Equal(t, "Paranoia is a tool for monitoring and securing Kubernetes clusters", rootCmd.Short)

	// Test persistent flags exist
	assert.NotNil(t, rootCmd.PersistentFlags().Lookup("watch-pods"))
	assert.NotNil(t, rootCmd.PersistentFlags().Lookup("watch-deployments"))
	assert.NotNil(t, rootCmd.PersistentFlags().Lookup("watch-secrets"))
	assert.NotNil(t, rootCmd.PersistentFlags().Lookup("watch-clusterroles"))
	//assert.NotNil(t, rootCmd.PersistentFlags().Lookup("check"))
	assert.NotNil(t, rootCmd.PersistentFlags().Lookup("deployment"))
	assert.NotNil(t, rootCmd.PersistentFlags().Lookup("risk"))
	assert.NotNil(t, rootCmd.PersistentFlags().Lookup("rbac"))
	assert.NotNil(t, rootCmd.PersistentFlags().Lookup("namespace"))
}

func TestRootCommandSubcommands(t *testing.T) {
	subcommands := []string{"watch", "check", "deployment", "rbac", "report", "report-html"}

	for _, subcmd := range subcommands {
		found := false
		for _, cmd := range rootCmd.Commands() {
			if cmd.Use == subcmd {
				found = true
				break
			}
		}
		assert.True(t, found, "Subcommand %s not found", subcmd)
	}
}

func TestWatchCommandNoResourcesSelected(t *testing.T) {
	cmd := createWatchCmd()

	// Capture output
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	// Set watch flag but no resources
	cmd.Flags().Set("watch", "true")

	// Execute command
	err := cmd.Execute()

	// Should not error but should warn about no resources
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "No resources selected")
}

func TestReportCmdWithoutNamespace(t *testing.T) {
	cmd := reportCmd()

	// Capture stderr
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	// Execute without namespace flag
	cmd.Execute()

	w.Close()
	var buf bytes.Buffer
	buf.ReadFrom(r)
	os.Stderr = oldStderr

	// Should output error about missing namespace
	assert.Contains(t, buf.String(), "Namespace is required")
}

func TestReportHTMLCmdFlagsDefaults(t *testing.T) {
	cmd := reportHTMLCmd()

	// Check default flag values
	outputFlag := cmd.Flags().Lookup("output")
	assert.NotNil(t, outputFlag)
	assert.Equal(t, "security-report.html", outputFlag.DefValue)

	portFlag := cmd.Flags().Lookup("port")
	assert.NotNil(t, portFlag)
	assert.Equal(t, "8080", portFlag.DefValue)
}

func TestMainFunctionExecution(t *testing.T) {
	assert.NotNil(t, rootCmd)

	// Verify all expected commands are registered
	expectedCommands := []string{"watch", "check", "deployment", "rbac", "report", "report-html"}
	actualCommands := make(map[string]bool)

	for _, cmd := range rootCmd.Commands() {
		actualCommands[cmd.Use] = true
	}

	for _, expected := range expectedCommands {
		assert.True(t, actualCommands[expected], "Command %s should be registered", expected)
	}
}

func TestGlobalFlags(t *testing.T) {
	tests := []struct {
		name     string
		flagName string
		flagType string
	}{
		{"watch-pods", "watch-pods", "bool"},
		{"watch-deployments", "watch-deployments", "bool"},
		{"watch-secrets", "watch-secrets", "bool"},
		{"watch-clusterroles", "watch-clusterroles", "bool"},
		//{"check", "check", "bool"},
		{"deployment", "deployment", "bool"},
		{"risk", "risk", "bool"},
		{"rbac", "rbac", "bool"},
		{"namespace", "namespace", "string"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := rootCmd.PersistentFlags().Lookup(tt.flagName)
			assert.NotNil(t, flag, "Flag %s should exist", tt.flagName)
			assert.Equal(t, tt.flagType, flag.Value.Type(), "Flag %s should be type %s", tt.flagName, tt.flagType)
		})
	}
}

func TestCommandErrorHandling(t *testing.T) {
	tests := []struct {
		name    string
		cmdFunc func() *cobra.Command
	}{
		{"watch", createWatchCmd},
		{"check", createCheckCmd},
		{"deployment", createDeploymentCmd},
		{"rbac", createRbacCmd},
		{"report", reportCmd},
		{"report-html", reportHTMLCmd},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := tt.cmdFunc()
			assert.NotNil(t, cmd)
			assert.NotNil(t, cmd.Run)
		})
	}
}
