package testutil

import (
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// Set up for watchers channel routing with type
type Watchers struct {
	Pods        *watch.FakeWatcher
	Deployments *watch.FakeWatcher
}

func NewTestClientset(objs ...runtime.Object) (*fake.Clientset, *Watchers) {
	// Common defaults you often need
	defaults := []runtime.Object{
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "test-node"}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "system:auth-delegator"}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "system:auth-delegator"}},
	}
	client := fake.NewSimpleClientset(append(defaults, objs...)...)
	// Enable watch reactors if your code uses watchers

	w := &Watchers{
		Pods:        watch.NewFake(),
		Deployments: watch.NewFake(),
	}

	// Pods
	client.Fake.PrependWatchReactor("pods",
		func(action k8stesting.Action) (bool, watch.Interface, error) {
			return true, w.Pods, nil
		},
	)

	client.Fake.PrependWatchReactor("deployments",
		func(action k8stesting.Action) (bool, watch.Interface, error) {
			return true, w.Deployments, nil
		},
	)
	// Secrets, ClusterRoles, etc. as needed
	client.Fake.PrependWatchReactor("*", func(action k8stesting.Action) (bool, watch.Interface, error) {
		return true, watch.NewFake(), nil
	})

	return client, w
}
