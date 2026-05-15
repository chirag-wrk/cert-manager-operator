package trustmanager

import (
	appsv1 "k8s.io/api/apps/v1"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
)

func (r *Reconciler) updateTrustManagerStatusFields(trustmanager *v1alpha1.TrustManager, deployment *appsv1.Deployment) error {
	changed := false

	for _, container := range deployment.Spec.Template.Spec.Containers {
		if container.Name == trustManagerContainerName {
			if trustmanager.Status.TrustManagerImage != container.Image {
				trustmanager.Status.TrustManagerImage = container.Image
				changed = true
			}
			break
		}
	}

	trustNamespace := trustmanager.Spec.TrustManagerConfig.TrustNamespace
	if trustNamespace == "" {
		trustNamespace = certManagerNamespace
	}
	if trustmanager.Status.TrustNamespace != trustNamespace {
		trustmanager.Status.TrustNamespace = trustNamespace
		changed = true
	}

	secretTargetsPolicy := string(trustmanager.Spec.TrustManagerConfig.SecretTargets.Policy)
	if secretTargetsPolicy == "" {
		secretTargetsPolicy = string(v1alpha1.SecretTargetsPolicyDisabled)
	}
	if trustmanager.Status.SecretTargetsPolicy != secretTargetsPolicy {
		trustmanager.Status.SecretTargetsPolicy = secretTargetsPolicy
		changed = true
	}

	defaultCAPackagePolicy := string(trustmanager.Spec.TrustManagerConfig.DefaultCAPackage.Policy)
	if defaultCAPackagePolicy == "" {
		defaultCAPackagePolicy = string(v1alpha1.DefaultCAPackagePolicyDisabled)
	}
	if trustmanager.Status.DefaultCAPackagePolicy != defaultCAPackagePolicy {
		trustmanager.Status.DefaultCAPackagePolicy = defaultCAPackagePolicy
		changed = true
	}

	filterExpiredPolicy := string(trustmanager.Spec.TrustManagerConfig.FilterExpiredCertificates)
	if filterExpiredPolicy == "" {
		filterExpiredPolicy = string(v1alpha1.FilterExpiredCertificatesPolicyDisabled)
	}
	if trustmanager.Status.FilterExpiredCertificatesPolicy != filterExpiredPolicy {
		trustmanager.Status.FilterExpiredCertificatesPolicy = filterExpiredPolicy
		changed = true
	}

	if changed {
		return r.updateStatus(r.ctx, trustmanager)
	}
	return nil
}
