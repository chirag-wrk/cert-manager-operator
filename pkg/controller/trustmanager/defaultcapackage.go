package trustmanager

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
)

// reconcileDefaultCAPackage ensures the default CA package ConfigMap is in sync with the
// trusted CA bundle from the operator namespace. Returns the SHA256 hash of the package
// data (to be set as an annotation on the Deployment), or empty string if not enabled.
func (r *Reconciler) reconcileDefaultCAPackage(trustmanager *v1alpha1.TrustManager, resourceLabels map[string]string) (string, error) {
	if trustmanager.Spec.TrustManagerConfig.DefaultCAPackage.Policy != v1alpha1.DefaultCAPackagePolicyEnabled {
		return "", nil
	}

	sourceKey := types.NamespacedName{
		Name:      trustedCABundleConfigMapName,
		Namespace: r.operatorNamespace,
	}

	sourceCM := &corev1.ConfigMap{}
	if err := r.Get(r.ctx, sourceKey, sourceCM); err != nil {
		return "", FromClientError(err, "failed to fetch trusted CA bundle configmap %s", sourceKey)
	}

	packageData, err := formatDefaultCAPackage(sourceCM)
	if err != nil {
		return "", NewIrrecoverableError(err, "failed to format default CA package from %s", sourceKey)
	}

	hash := computeCAPackageHash(packageData)

	desiredCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      defaultCAPackageConfigMapName,
			Namespace: certManagerNamespace,
			Labels:    resourceLabels,
		},
		Data: packageData,
	}

	configmapKey := client.ObjectKeyFromObject(desiredCM)
	r.log.V(4).Info("reconciling default CA package configmap", "name", configmapKey)

	fetchedCM := &corev1.ConfigMap{}
	exist, err := r.Exists(r.ctx, configmapKey, fetchedCM)
	if err != nil {
		return "", FromClientError(err, "failed to check default CA package configmap %s already exists", configmapKey)
	}

	if exist && hasObjectChanged(desiredCM, fetchedCM) {
		r.log.V(1).Info("default CA package configmap has been modified, updating to desired state", "name", configmapKey)
		if err := r.UpdateWithRetry(r.ctx, desiredCM); err != nil {
			return "", FromClientError(err, "failed to update default CA package configmap %s", configmapKey)
		}
		r.eventRecorder.Eventf(trustmanager, corev1.EventTypeNormal, "Reconciled", "configmap resource %s reconciled back to desired state", configmapKey)
	} else {
		r.log.V(4).Info("default CA package configmap already exists and is in expected state", "name", configmapKey)
	}
	if !exist {
		if err := r.Create(r.ctx, desiredCM); err != nil {
			return "", FromClientError(err, "failed to create default CA package configmap %s", configmapKey)
		}
		r.eventRecorder.Eventf(trustmanager, corev1.EventTypeNormal, "Reconciled", "configmap resource %s created", configmapKey)
	}

	return hash, nil
}

// formatDefaultCAPackage converts the raw CA bundle ConfigMap data into the JSON format
// expected by trust-manager's default package feature.
//
// trust-manager expects the default CA package file to contain PEM-encoded certificates.
// We format it as a single JSON object {"trust-bundle.pem": "<pem-content>"} written
// as individual entries in ConfigMap.Data.
func formatDefaultCAPackage(sourceCM *corev1.ConfigMap) (map[string]string, error) {
	const caDataKey = "ca-bundle.crt"
	const packageFileKey = "trust-bundle.pem"

	caBundle, ok := sourceCM.Data[caDataKey]
	if !ok || caBundle == "" {
		// Fallback: use any value present in the ConfigMap
		for _, v := range sourceCM.Data {
			if v != "" {
				caBundle = v
				break
			}
		}
	}

	if caBundle == "" {
		return nil, fmt.Errorf("trusted CA bundle configmap %s/%s contains no usable CA data", sourceCM.Namespace, sourceCM.Name)
	}

	// Encode the bundle as a JSON string to allow embedding in the package manifest
	encoded, err := json.Marshal(caBundle)
	if err != nil {
		return nil, fmt.Errorf("failed to encode CA bundle as JSON: %w", err)
	}

	return map[string]string{
		packageFileKey: string(encoded),
	}, nil
}

// computeCAPackageHash returns a hex SHA256 hash of the ConfigMap data, used to
// annotate the Deployment and trigger a rolling restart when the bundle changes.
func computeCAPackageHash(data map[string]string) string {
	h := sha256.New()
	for k, v := range data {
		h.Write([]byte(k))
		h.Write([]byte(v))
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}
