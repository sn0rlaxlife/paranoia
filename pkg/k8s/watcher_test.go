package k8s

import (
	"testing"
	"time"

	"kspm/pkg/k8s/internal/testutil"

	"github.com/stretchr/testify/assert"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

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

func TestSecurityEventHandler(t *testing.T) {
	handler := ConsoleSecurityEventHandler{}

	event := SecurityEvent{
		Timestamp:    time.Now(),
		Severity:     "INFO",
		ResourceType: "Pod",
		ResourceName: "test-pod",
		Namespace:    "default",
		Message:      "Test message",
	}

	// Should not panic
	assert.NotPanics(t, func() {
		handler.HandleEvent(event)
	})
}

func TestRecordingSecurityEventHandler(t *testing.T) {
	recorder := &RecordingSecurityEventHandler{}

	event1 := SecurityEvent{
		Timestamp:    time.Now(),
		Severity:     "WARNING",
		ResourceType: "Secret",
		ResourceName: "test-secret",
		Namespace:    "default",
		Message:      "Sensitive data detected",
	}

	event2 := SecurityEvent{
		Timestamp:    time.Now(),
		Severity:     "CRITICAL",
		ResourceType: "Pod",
		ResourceName: "privileged-pod",
		Namespace:    "kube-system",
		Message:      "Privileged container detected",
	}

	recorder.HandleEvent(event1)
	recorder.HandleEvent(event2)

	snapshot := recorder.SnapShot()
	assert.Len(t, snapshot, 2)
	assert.Equal(t, "WARNING", snapshot[0].Severity)
	assert.Equal(t, "CRITICAL", snapshot[1].Severity)
}

func TestMultiSecurityEventHandler(t *testing.T) {
	recorder1 := &RecordingSecurityEventHandler{}
	recorder2 := &RecordingSecurityEventHandler{}

	multi := MultiSecurityEventHandler{
		Handlers: []SecurityEventHandler{recorder1, recorder2},
	}

	event := SecurityEvent{
		Timestamp:    time.Now(),
		Severity:     "INFO",
		ResourceType: "Deployment",
		ResourceName: "test-deploy",
		Namespace:    "default",
		Message:      "Test",
	}

	multi.HandleEvent(event)

	assert.Len(t, recorder1.SnapShot(), 1)
	assert.Len(t, recorder2.SnapShot(), 1)
}

func TestSetSecurityEventHandler(t *testing.T) {
	recorder := &RecordingSecurityEventHandler{}
	SetSecurityEventHandler(recorder)

	// Report event should use the new handler
	reportSecurityEvent("INFO", "Test", "test-resource", "default", "Test message")

	snapshot := recorder.SnapShot()
	assert.Len(t, snapshot, 1)
	assert.Equal(t, "INFO", snapshot[0].Severity)
}

func TestCheckPodSecurity(t *testing.T) {
	recorder := &RecordingSecurityEventHandler{}
	SetSecurityEventHandler(recorder)

	tests := []struct {
		name          string
		pod           *corev1.Pod
		expectedCount int
	}{
		{
			name: "privileged pod",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "privileged-pod",
					Namespace: "default",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "test-container",
							Image: "nginx:latest",
							SecurityContext: &corev1.SecurityContext{
								Privileged: func() *bool { b := true; return &b }(),
							},
						},
					},
				},
			},
			expectedCount: 1, // At least privileged warning
		},
		{
			name: "hostNetwork pod",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "hostnet-pod",
					Namespace: "default",
				},
				Spec: corev1.PodSpec{
					HostNetwork: true,
					Containers: []corev1.Container{
						{
							Name:  "test-container",
							Image: "nginx:1.19",
						},
					},
				},
			},
			expectedCount: 0, // HostNetwork triggers reportSecurityEvent
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder.Events = []SecurityEvent{} // Reset

			CheckPodSecurity(tt.pod)

			snapshot := recorder.SnapShot()
			if tt.expectedCount > 0 {
				assert.GreaterOrEqual(t, len(snapshot), tt.expectedCount)
			}
		})
	}
}

func TestCheckDeploymentSecurity(t *testing.T) {
	recorder := &RecordingSecurityEventHandler{}
	SetSecurityEventHandler(recorder)

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-deployment",
			Namespace: "default",
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "test-container",
							Image: "nginx:latest",
						},
					},
				},
			},
		},
	}

	CheckDeploymentSecurity(deployment)

	snapshot := recorder.SnapShot()
	// Should have at least one event (no security context or resource limits)
	assert.GreaterOrEqual(t, len(snapshot), 1)
}

func TestCheckClusterRoleSecurity(t *testing.T) {
	recorder := &RecordingSecurityEventHandler{}
	SetSecurityEventHandler(recorder)

	tests := []struct {
		name           string
		role           *rbacv1.ClusterRole
		expectCritical bool
	}{
		{
			name: "wildcard resources",
			role: &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "wildcard-role",
				},
				Rules: []rbacv1.PolicyRule{
					{
						Verbs:     []string{"get", "list"},
						Resources: []string{"*"},
					},
				},
			},
			expectCritical: true,
		},
		{
			name: "wildcard verbs",
			role: &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "wildcard-verbs-role",
				},
				Rules: []rbacv1.PolicyRule{
					{
						Verbs:     []string{"*"},
						Resources: []string{"pods"},
					},
				},
			},
			expectCritical: false, // WARNING not CRITICAL
		},
		{
			name: "safe role",
			role: &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "safe-role",
				},
				Rules: []rbacv1.PolicyRule{
					{
						Verbs:     []string{"get", "list"},
						Resources: []string{"pods"},
					},
				},
			},
			expectCritical: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder.Events = []SecurityEvent{} // Reset

			CheckClusterRoleSecurity(tt.role)

			snapshot := recorder.SnapShot()
			if tt.expectCritical {
				found := false
				for _, event := range snapshot {
					if event.Severity == "CRITICAL" {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected CRITICAL event")
			}
		})
	}
}

func TestCheckSecretSecurity(t *testing.T) {
	recorder := &RecordingSecurityEventHandler{}
	SetSecurityEventHandler(recorder)

	tests := []struct {
		name     string
		secret   *corev1.Secret
		hasEvent bool
	}{
		{
			name: "default service account token",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "default-token-xyz",
					Namespace: "default",
				},
				Type: corev1.SecretTypeServiceAccountToken,
			},
			hasEvent: true,
		},
		{
			name: "secret with password",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "db-credentials",
					Namespace: "default",
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					"password": []byte("secret"),
				},
			},
			hasEvent: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder.Events = []SecurityEvent{} // Reset

			CheckSecretSecurity(tt.secret)

			snapshot := recorder.SnapShot()
			if tt.hasEvent {
				assert.Greater(t, len(snapshot), 0)
			}
		})
	}
}

func TestStartKubernetesWatchers(t *testing.T) {
	clientset, watchers := testutil.NewTestClientset()

	options := map[string]bool{
		"pods":         true,
		"deployments":  true,
		"secrets":      false,
		"clusterRoles": false,
	}

	stopChannels := StartKubernetesWatchers(clientset, options)

	// Add a event
	// Now push a fake event into the pod watch stream
	watchers.Pods.Add(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: "default"}})

	// Should return 2 stop channels (pods + deployments)
	assert.Len(t, stopChannels, 2)

	// Clean up
	for _, ch := range stopChannels {
		close(ch)
	}
}
func TestStartKubernetesWatchers_Options(t *testing.T) {
	clientset := fake.NewSimpleClientset()

	options := map[string]bool{
		"pods":        true,
		"deployments": true,
		"secrets":     false,
	}

	stops := StartKubernetesWatchers(clientset, options)
	assert.Len(t, stops, 2)

	for _, ch := range stops {
		close(ch)
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		name     string
		slice    []string
		value    string
		expected bool
	}{
		{"found", []string{"a", "b", "c"}, "b", true},
		{"not found", []string{"a", "b", "c"}, "d", false},
		{"empty slice", []string{}, "a", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := contains(tt.slice, tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}
