package trustmanager

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/operator/assets"
)

func (r *Reconciler) createOrApplyServices(trustmanager *v1alpha1.TrustManager, resourceLabels map[string]string, isCreate bool) error {
	webhookSvc := r.getServiceObject(resourceLabels)
	if err := r.createOrApplyService(trustmanager, webhookSvc, isCreate); err != nil {
		return err
	}

	metricsSvc := r.getMetricsServiceObject(resourceLabels)
	if err := r.createOrApplyService(trustmanager, metricsSvc, isCreate); err != nil {
		return err
	}

	return nil
}

func (r *Reconciler) createOrApplyService(trustmanager *v1alpha1.TrustManager, svc *corev1.Service, isCreate bool) error {
	serviceName := fmt.Sprintf("%s/%s", svc.GetNamespace(), svc.GetName())
	r.log.V(4).Info("reconciling service resource", "name", serviceName)
	fetched := &corev1.Service{}
	exist, err := r.Exists(r.ctx, client.ObjectKeyFromObject(svc), fetched)
	if err != nil {
		return FromClientError(err, "failed to check %s service resource already exists", serviceName)
	}

	if exist && isCreate {
		r.eventRecorder.Eventf(trustmanager, corev1.EventTypeWarning, "ResourceAlreadyExists", "%s service resource already exists, maybe from previous installation", serviceName)
	}
	if exist && hasObjectChanged(svc, fetched) {
		r.log.V(1).Info("service has been modified, updating to desired state", "name", serviceName)
		if err := r.UpdateWithRetry(r.ctx, svc); err != nil {
			return FromClientError(err, "failed to update %s service resource", serviceName)
		}
		r.eventRecorder.Eventf(trustmanager, corev1.EventTypeNormal, "Reconciled", "service resource %s reconciled back to desired state", serviceName)
	} else {
		r.log.V(4).Info("service resource already exists and is in expected state", "name", serviceName)
	}
	if !exist {
		if err := r.Create(r.ctx, svc); err != nil {
			return FromClientError(err, "failed to create %s service resource", serviceName)
		}
		r.eventRecorder.Eventf(trustmanager, corev1.EventTypeNormal, "Reconciled", "service resource %s created", serviceName)
	}
	return nil
}

func (r *Reconciler) getServiceObject(resourceLabels map[string]string) *corev1.Service {
	service := decodeServiceObjBytes(assets.MustAsset(serviceAssetName))
	updateResourceLabels(service, resourceLabels)
	return service
}

func (r *Reconciler) getMetricsServiceObject(resourceLabels map[string]string) *corev1.Service {
	service := decodeServiceObjBytes(assets.MustAsset(metricsServiceAssetName))
	updateResourceLabels(service, resourceLabels)
	return service
}
