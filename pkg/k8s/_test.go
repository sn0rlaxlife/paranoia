package k8s

import (
	"testing"
)

func TestNewClientSet(t *testing.T) {
	clientset := NewClientSet()
	if clientset == nil {
		t.Errorf("NewClientSet() returned nil")
	}
}
