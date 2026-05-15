package trustmanager

import (
	"fmt"
	"maps"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
)

func (r *Reconciler) reconcileTrustManagerDeployment(trustmanager *v1alpha1.TrustManager, isCreate bool) error {
	// Merge user-provided labels with controller default labels; operator labels take precedence.
	resourceLabels := make(map[string]string)
	if trustmanager.Spec.ControllerConfig != nil && len(trustmanager.Spec.ControllerConfig.Labels) != 0 {
		maps.Copy(resourceLabels, trustmanager.Spec.ControllerConfig.Labels)
	}
	maps.Copy(resourceLabels, controllerDefaultResourceLabels)

	if err := r.createOrApplyServiceAccounts(trustmanager, resourceLabels, isCreate); err != nil {
		r.log.Error(err, "failed to reconcile serviceaccount resource")
		return err
	}

	if err := r.createOrApplyServices(trustmanager, resourceLabels, isCreate); err != nil {
		r.log.Error(err, "failed to reconcile service resources")
		return err
	}

	if err := r.createOrApplyRBACResource(trustmanager, resourceLabels, isCreate); err != nil {
		r.log.Error(err, "failed to reconcile RBAC resources")
		return err
	}

	if err := r.createOrApplyCertificateResources(trustmanager, resourceLabels, isCreate); err != nil {
		r.log.Error(err, "failed to reconcile certificate resources")
		return err
	}

	if err := r.createOrApplyValidatingWebhookConfiguration(trustmanager, resourceLabels, isCreate); err != nil {
		r.log.Error(err, "failed to reconcile validatingwebhookconfiguration resource")
		return err
	}

	caPackageHash, err := r.reconcileDefaultCAPackage(trustmanager, resourceLabels)
	if err != nil {
		r.log.Error(err, "failed to reconcile default CA package")
		return fmt.Errorf("failed to reconcile default CA package: %w", err)
	}

	if err := r.createOrApplyDeployments(trustmanager, resourceLabels, caPackageHash, isCreate); err != nil {
		r.log.Error(err, "failed to reconcile deployment resource")
		return err
	}

	r.log.V(4).Info("finished reconciliation of trust-manager", "name", trustmanager.GetName())
	return nil
}
