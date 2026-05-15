package library

import (
	"context"
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
)

const trustManagerObjectName = "cluster"

// TrustManagerOption is a functional option for building TrustManager CRs.
type TrustManagerOption func(*v1alpha1.TrustManager)

// TrustManagerCR returns a TrustManager CR named "cluster" with options applied.
func TrustManagerCR(opts ...TrustManagerOption) *v1alpha1.TrustManager {
	tm := &v1alpha1.TrustManager{
		ObjectMeta: metav1.ObjectMeta{
			Name: trustManagerObjectName,
		},
	}
	for _, opt := range opts {
		opt(tm)
	}
	return tm
}

// WithDefaultCAPackageEnabled sets the defaultCAPackage policy to Enabled.
func WithDefaultCAPackageEnabled() TrustManagerOption {
	return func(tm *v1alpha1.TrustManager) {
		tm.Spec.TrustManagerConfig.DefaultCAPackage.Policy = v1alpha1.DefaultCAPackagePolicyEnabled
	}
}

// WithSecretTargets sets the secretTargets policy.
func WithSecretTargets(policy v1alpha1.SecretTargetsPolicy, secrets ...string) TrustManagerOption {
	return func(tm *v1alpha1.TrustManager) {
		tm.Spec.TrustManagerConfig.SecretTargets.Policy = policy
		tm.Spec.TrustManagerConfig.SecretTargets.AuthorizedSecrets = secrets
	}
}

// WithTrustNamespace sets the trust namespace.
func WithTrustNamespace(ns string) TrustManagerOption {
	return func(tm *v1alpha1.TrustManager) {
		tm.Spec.TrustManagerConfig.TrustNamespace = ns
	}
}

// CreateTrustManager creates a TrustManager CR named "cluster" with the given spec.
func CreateTrustManager(ctx context.Context, c client.Client, spec v1alpha1.TrustManagerSpec) (*v1alpha1.TrustManager, error) {
	tm := &v1alpha1.TrustManager{
		ObjectMeta: metav1.ObjectMeta{
			Name: trustManagerObjectName,
		},
		Spec: spec,
	}
	if err := c.Create(ctx, tm); err != nil {
		return nil, fmt.Errorf("failed to create TrustManager CR: %w", err)
	}
	return tm, nil
}

// DeleteTrustManager deletes the singleton TrustManager CR.
func DeleteTrustManager(ctx context.Context, c client.Client) error {
	tm := &v1alpha1.TrustManager{}
	tm.Name = trustManagerObjectName
	if err := c.Delete(ctx, tm); err != nil {
		return fmt.Errorf("failed to delete TrustManager CR: %w", err)
	}
	return nil
}

// WaitForTrustManagerReady polls until the TrustManager CR has Ready=True condition.
func WaitForTrustManagerReady(ctx context.Context, c client.Client, timeout time.Duration) error {
	return wait.PollUntilContextTimeout(ctx, 5*time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		tm := &v1alpha1.TrustManager{}
		if err := c.Get(ctx, client.ObjectKey{Name: trustManagerObjectName}, tm); err != nil {
			return false, nil
		}
		cond := GetTrustManagerCondition(tm, v1alpha1.Ready)
		if cond == nil {
			return false, nil
		}
		if cond.Status == metav1.ConditionTrue {
			return true, nil
		}
		degraded := GetTrustManagerCondition(tm, v1alpha1.Degraded)
		if degraded != nil && degraded.Status == metav1.ConditionTrue {
			return false, fmt.Errorf("TrustManager is degraded: %s", degraded.Message)
		}
		return false, nil
	})
}

// WaitForTrustManagerDegraded polls until the TrustManager CR has Degraded=True.
// If reasonSubstring is non-empty, it also checks that the degraded message contains it.
func WaitForTrustManagerDegraded(ctx context.Context, c client.Client, timeout time.Duration, reasonSubstring string) error {
	return wait.PollUntilContextTimeout(ctx, 5*time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		tm := &v1alpha1.TrustManager{}
		if err := c.Get(ctx, client.ObjectKey{Name: trustManagerObjectName}, tm); err != nil {
			return false, nil
		}
		cond := GetTrustManagerCondition(tm, v1alpha1.Degraded)
		if cond == nil || cond.Status != metav1.ConditionTrue {
			return false, nil
		}
		if reasonSubstring != "" && !strings.Contains(cond.Message, reasonSubstring) {
			return false, nil
		}
		return true, nil
	})
}

// GetTrustManagerCondition extracts a named condition from TrustManager status.
func GetTrustManagerCondition(tm *v1alpha1.TrustManager, condType string) *metav1.Condition {
	return meta.FindStatusCondition(tm.Status.Conditions, condType)
}

