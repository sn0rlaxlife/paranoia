package main

import (
	"bytes"
	"fmt"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/kubernetes"
)

func TestMain(m *testing.M) {
	// Redirect stdout to buffer
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Run tests
	code := m.Run()

	// Reset stdout
	w.Close()
	os.Stdout = old

	// Print captured output
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	fmt.Println(buf.String())

	// Exit with test code
	os.Exit(code)
}

func TestMainFunction(t *testing.T) {
	// Mock initClient function
	newInitClient := func() (*kubernetes.Clientset, error) {
		return nil, fmt.Errorf("mock error")
	}

	// Capture stdout
	var buf bytes.Buffer
	os.Stdout = &buf

	// Run main function
	main()

	// Assert error message
	expected := "Error initializing Kubernetes client: mock error\n"
	assert.Equal(t, expected, buf.String())
}

func TestWatchCommand(t *testing.T) {
	// Mock initClient function
	initClient = func() (*kubernetes.Clientset, error) {
		return nil, fmt.Errorf("mock error")
	}

	// Capture stdout
	var buf bytes.Buffer
	os.Stdout = os.NewFile(uintptr(syscall.Stdout), "/dev/stdout")
	// Set watchFlag
	watchFlag = true

	// Run main function
	main()

	// Assert error message
	expected := "Error initializing Kubernetes client: mock error\n"
	assert.Equal(t, expected, buf.String())
}

func TestCheckCommand(t *testing.T) {
	// Mock initClient function
	initClient = func() (*kubernetes.Clientset, error) {
		return nil, fmt.Errorf("mock error")
	}

	// Capture stdout
	var buf bytes.Buffer
	os.Stdout = &buf

	// Set checkFlag
	checkFlag = true

	// Run main function
	main()

	// Assert error message
	expected := "Error initializing Kubernetes client: mock error\n"
	assert.Equal(t, expected, buf.String())
}

func TestDeploymentCommand(t *testing.T) {
	// Mock initClient function
	initClient = func() (*kubernetes.Clientset, error) {
		return nil, fmt.Errorf("mock error")
	}

	// Capture stdout
	var buf bytes.Buffer
	os.Stdout = &buf

	// Set deploymentFlag
	deploymentFlag = true

	// Run main function
	main()

	// Assert error message
	expected := "Error initializing Kubernetes client: mock error\n"
	assert.Equal(t, expected, buf.String())
}

func TestRBACCommand(t *testing.T) {
	// Mock initClient function
	initClient = func() (*kubernetes.Clientset, error) {
		return nil, fmt.Errorf("mock error")
	}

	// Capture stdout
	var buf bytes.Buffer
	os.Stdout = &buf

	// Set rbacFlag
	rbacFlag = true

	// Run main function
	main()

	// Assert error message
	expected := "Error initializing Kubernetes client: mock error\n"
	assert.Equal(t, expected, buf.String())
}

func TestRiskCommand(t *testing.T) {
	// Mock initClient function
	initClient = func() (*kubernetes.Clientset, error) {
		return nil, fmt.Errorf("mock error")
	}

	// Capture stdout
	var buf bytes.Buffer
	os.Stdout = &buf

	// Set riskFlag
	riskFlag = true

	// Run main function
	main()

	// Assert error message
	expected := "Error initializing Kubernetes client: mock error\n"
	assert.Equal(t, expected, buf.String())
}

func TestInvalidOption(t *testing.T) {
	// Capture stdout
	var buf bytes.Buffer
	os.Stdout = &buf

	// Run main function with invalid option
	main()

	// Assert error message
	expected := "Invalid option\n"
	assert.Equal(t, expected, buf.String())
}
