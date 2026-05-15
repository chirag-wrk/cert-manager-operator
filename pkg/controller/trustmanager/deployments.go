package trustmanager

import (
	"fmt"
	"os"
	"reflect"
	"unsafe"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1validation "k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kubernetes/pkg/apis/core"
	corevalidation "k8s.io/kubernetes/pkg/apis/core/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/operator/assets"
)

const (
	defaultCAPackageVolumeName      = "default-ca-package"
	defaultCAPackageVolumeMountPath = "/default-package"
)

func (r *Reconciler) createOrApplyDeployments(trustmanager *v1alpha1.TrustManager, resourceLabels map[string]string, caPackageHash string, isCreate bool) error {
	desired, err := r.getDeploymentObject(trustmanager, resourceLabels, caPackageHash)
	if err != nil {
		return fmt.Errorf("failed to generate deployment resource: %w", err)
	}

	deploymentName := fmt.Sprintf("%s/%s", desired.GetNamespace(), desired.GetName())
	r.log.V(4).Info("reconciling deployment resource", "name", deploymentName)
	fetched := &appsv1.Deployment{}
	exist, err := r.Exists(r.ctx, client.ObjectKeyFromObject(desired), fetched)
	if err != nil {
		return FromClientError(err, "failed to check %s deployment resource already exists", deploymentName)
	}

	if exist && isCreate {
		r.eventRecorder.Eventf(trustmanager, corev1.EventTypeWarning, "ResourceAlreadyExists", "%s deployment resource already exists, maybe from previous installation", deploymentName)
	}
	if exist && hasObjectChanged(desired, fetched) {
		r.log.V(1).Info("deployment has been modified, updating to desired state", "name", deploymentName)
		if err := r.UpdateWithRetry(r.ctx, desired); err != nil {
			return FromClientError(err, "failed to update %s deployment resource", deploymentName)
		}
		r.eventRecorder.Eventf(trustmanager, corev1.EventTypeNormal, "Reconciled", "deployment resource %s reconciled back to desired state", deploymentName)
	} else {
		r.log.V(4).Info("deployment resource already exists and is in expected state", "name", deploymentName)
	}
	if !exist {
		if err := r.Create(r.ctx, desired); err != nil {
			return FromClientError(err, "failed to create %s deployment resource", deploymentName)
		}
		r.eventRecorder.Eventf(trustmanager, corev1.EventTypeNormal, "Reconciled", "deployment resource %s created", deploymentName)
	}

	if err := r.updateTrustManagerStatusFields(trustmanager, desired); err != nil {
		return FromClientError(err, "failed to update trustmanager status after deployment reconciliation")
	}

	return nil
}

func (r *Reconciler) getDeploymentObject(trustmanager *v1alpha1.TrustManager, resourceLabels map[string]string, caPackageHash string) (*appsv1.Deployment, error) {
	deployment := decodeDeploymentObjBytes(assets.MustAsset(deploymentAssetName))

	updateResourceLabels(deployment, resourceLabels)
	updatePodTemplateLabels(deployment, resourceLabels)

	if err := r.updateImage(deployment); err != nil {
		return nil, NewIrrecoverableError(err, "failed to update image for trust-manager deployment")
	}

	updateArgList(deployment, trustmanager)

	if err := updateResourceRequirement(deployment, trustmanager); err != nil {
		return nil, fmt.Errorf("failed to update resource requirements: %w", err)
	}
	if err := updateAffinityRules(deployment, trustmanager); err != nil {
		return nil, fmt.Errorf("failed to update affinity rules: %w", err)
	}
	if err := updatePodTolerations(deployment, trustmanager); err != nil {
		return nil, fmt.Errorf("failed to update pod tolerations: %w", err)
	}
	if err := updateNodeSelector(deployment, trustmanager); err != nil {
		return nil, fmt.Errorf("failed to update node selector: %w", err)
	}

	if trustmanager.Spec.TrustManagerConfig.DefaultCAPackage.Policy == v1alpha1.DefaultCAPackagePolicyEnabled {
		updateDefaultCAPackageVolume(deployment, caPackageHash)
	}

	return deployment, nil
}

func (r *Reconciler) updateImage(deployment *appsv1.Deployment) error {
	image := os.Getenv(trustManagerImageNameEnvVarName)
	if image == "" {
		return fmt.Errorf("%s environment variable with trust-manager image not set", trustManagerImageNameEnvVarName)
	}
	for i, container := range deployment.Spec.Template.Spec.Containers {
		if container.Name == trustManagerContainerName {
			deployment.Spec.Template.Spec.Containers[i].Image = image
		}
	}
	return nil
}

func updatePodTemplateLabels(deployment *appsv1.Deployment, resourceLabels map[string]string) {
	deployment.Spec.Template.Labels = resourceLabels
}

func updateArgList(deployment *appsv1.Deployment, trustmanager *v1alpha1.TrustManager) {
	cfg := trustmanager.Spec.TrustManagerConfig

	trustNamespace := cfg.TrustNamespace
	if trustNamespace == "" {
		trustNamespace = certManagerNamespace
	}

	logLevel := cfg.LogLevel
	if logLevel == 0 {
		logLevel = 1
	}

	logFormat := cfg.LogFormat
	if logFormat == "" {
		logFormat = "text"
	}

	args := []string{
		fmt.Sprintf("--log-level=%d", logLevel),
		fmt.Sprintf("--log-format=%s", logFormat),
		fmt.Sprintf("--trust-namespace=%s", trustNamespace),
		"--webhook-host=0.0.0.0",
		"--webhook-port=6443",
		"--webhook-certificate-dir=/tls",
	}

	if cfg.FilterExpiredCertificates == v1alpha1.FilterExpiredCertificatesPolicyEnabled {
		args = append(args, "--filter-expired-certificates=true")
	}

	if cfg.DefaultCAPackage.Policy == v1alpha1.DefaultCAPackagePolicyEnabled {
		args = append(args, fmt.Sprintf("--default-package-location=%s/trust-bundle.pem", defaultCAPackageVolumeMountPath))
	}

	for i, container := range deployment.Spec.Template.Spec.Containers {
		if container.Name == trustManagerContainerName {
			deployment.Spec.Template.Spec.Containers[i].Args = args
		}
	}
}

// updateDefaultCAPackageVolume adds (or updates) the default CA package volume and volume mount
// on the Deployment. The caPackageHash is set as a pod template annotation to trigger rolling
// restarts when the CA bundle content changes.
func updateDefaultCAPackageVolume(deployment *appsv1.Deployment, caPackageHash string) {
	desiredVolume := corev1.Volume{
		Name: defaultCAPackageVolumeName,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: defaultCAPackageConfigMapName,
				},
			},
		},
	}

	desiredVolumeMount := corev1.VolumeMount{
		Name:      defaultCAPackageVolumeName,
		MountPath: defaultCAPackageVolumeMountPath,
		ReadOnly:  true,
	}

	for i, container := range deployment.Spec.Template.Spec.Containers {
		if container.Name == trustManagerContainerName {
			vmExists := false
			for j, vm := range container.VolumeMounts {
				if vm.Name == defaultCAPackageVolumeName {
					deployment.Spec.Template.Spec.Containers[i].VolumeMounts[j] = desiredVolumeMount
					vmExists = true
					break
				}
			}
			if !vmExists {
				deployment.Spec.Template.Spec.Containers[i].VolumeMounts = append(
					deployment.Spec.Template.Spec.Containers[i].VolumeMounts,
					desiredVolumeMount,
				)
			}
			break
		}
	}

	volExists := false
	for i, vol := range deployment.Spec.Template.Spec.Volumes {
		if vol.Name == defaultCAPackageVolumeName {
			deployment.Spec.Template.Spec.Volumes[i] = desiredVolume
			volExists = true
			break
		}
	}
	if !volExists {
		deployment.Spec.Template.Spec.Volumes = append(deployment.Spec.Template.Spec.Volumes, desiredVolume)
	}

	if caPackageHash != "" {
		if deployment.Spec.Template.Annotations == nil {
			deployment.Spec.Template.Annotations = make(map[string]string)
		}
		deployment.Spec.Template.Annotations[defaultCAPackageHashAnnotation] = caPackageHash
	}
}

func updateResourceRequirement(deployment *appsv1.Deployment, trustmanager *v1alpha1.TrustManager) error {
	if reflect.ValueOf(trustmanager.Spec.TrustManagerConfig.Resources).IsZero() {
		return nil
	}
	if err := validateResourceRequirements(trustmanager.Spec.TrustManagerConfig.Resources,
		field.NewPath("spec", "trustManagerConfig")); err != nil {
		return err
	}
	for i := range deployment.Spec.Template.Spec.Containers {
		deployment.Spec.Template.Spec.Containers[i].Resources = trustmanager.Spec.TrustManagerConfig.Resources
	}
	return nil
}

func updateAffinityRules(deployment *appsv1.Deployment, trustmanager *v1alpha1.TrustManager) error {
	if trustmanager.Spec.TrustManagerConfig.Affinity == nil {
		return nil
	}
	if err := validateAffinityRules(trustmanager.Spec.TrustManagerConfig.Affinity,
		field.NewPath("spec", "trustManagerConfig")); err != nil {
		return err
	}
	deployment.Spec.Template.Spec.Affinity = trustmanager.Spec.TrustManagerConfig.Affinity
	return nil
}

func updatePodTolerations(deployment *appsv1.Deployment, trustmanager *v1alpha1.TrustManager) error {
	if trustmanager.Spec.TrustManagerConfig.Tolerations == nil {
		return nil
	}
	if err := validateTolerationsConfig(trustmanager.Spec.TrustManagerConfig.Tolerations,
		field.NewPath("spec", "trustManagerConfig")); err != nil {
		return err
	}
	deployment.Spec.Template.Spec.Tolerations = trustmanager.Spec.TrustManagerConfig.Tolerations
	return nil
}

func updateNodeSelector(deployment *appsv1.Deployment, trustmanager *v1alpha1.TrustManager) error {
	if trustmanager.Spec.TrustManagerConfig.NodeSelector == nil {
		return nil
	}
	if err := validateNodeSelectorConfig(trustmanager.Spec.TrustManagerConfig.NodeSelector,
		field.NewPath("spec", "trustManagerConfig")); err != nil {
		return err
	}
	deployment.Spec.Template.Spec.NodeSelector = trustmanager.Spec.TrustManagerConfig.NodeSelector
	return nil
}

func validateNodeSelectorConfig(nodeSelector map[string]string, fldPath *field.Path) error {
	return metav1validation.ValidateLabels(nodeSelector, fldPath.Child("nodeSelector")).ToAggregate()
}

func validateTolerationsConfig(tolerations []corev1.Toleration, fldPath *field.Path) error {
	convTolerations := *(*[]core.Toleration)(unsafe.Pointer(&tolerations))
	return corevalidation.ValidateTolerations(convTolerations, fldPath.Child("tolerations")).ToAggregate()
}

func validateResourceRequirements(requirements corev1.ResourceRequirements, fldPath *field.Path) error {
	convRequirements := *(*core.ResourceRequirements)(unsafe.Pointer(&requirements))
	return corevalidation.ValidateContainerResourceRequirements(&convRequirements, nil, fldPath.Child("resources"), corevalidation.PodValidationOptions{}).ToAggregate()
}

func validateAffinityRules(affinity *corev1.Affinity, fldPath *field.Path) error {
	convAffinity := (*core.Affinity)(unsafe.Pointer(affinity))
	return validateAffinity(convAffinity, corevalidation.PodValidationOptions{}, fldPath.Child("affinity")).ToAggregate()
}
