package trustmanager

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/operator/assets"
)

func (r *Reconciler) createOrApplyRBACResource(trustmanager *v1alpha1.TrustManager, resourceLabels map[string]string, isCreate bool) error {
	serviceAccount := decodeServiceAccountObjBytes(assets.MustAsset(serviceAccountAssetName)).GetName()
	trustNamespace := trustmanager.Spec.TrustManagerConfig.TrustNamespace
	if trustNamespace == "" {
		trustNamespace = certManagerNamespace
	}

	if err := r.createOrApplyClusterRoles(trustmanager, resourceLabels, isCreate); err != nil {
		r.log.Error(err, "failed to reconcile clusterrole resource")
		return err
	}

	if err := r.createOrApplyClusterRoleBindings(trustmanager, serviceAccount, resourceLabels, isCreate); err != nil {
		r.log.Error(err, "failed to reconcile clusterrolebinding resource")
		return err
	}

	if err := r.createOrApplyRoles(trustmanager, trustNamespace, resourceLabels, isCreate); err != nil {
		r.log.Error(err, "failed to reconcile role resource")
		return err
	}

	if err := r.createOrApplyRoleBindings(trustmanager, serviceAccount, trustNamespace, resourceLabels, isCreate); err != nil {
		r.log.Error(err, "failed to reconcile rolebinding resource")
		return err
	}

	if err := r.createOrApplyLeaderElectionRole(trustmanager, resourceLabels, isCreate); err != nil {
		r.log.Error(err, "failed to reconcile leader election role resource")
		return err
	}

	if err := r.createOrApplyLeaderElectionRoleBinding(trustmanager, serviceAccount, resourceLabels, isCreate); err != nil {
		r.log.Error(err, "failed to reconcile leader election rolebinding resource")
		return err
	}

	return nil
}

func (r *Reconciler) createOrApplyClusterRoles(trustmanager *v1alpha1.TrustManager, resourceLabels map[string]string, isCreate bool) error {
	desired := r.getClusterRoleObject(trustmanager, resourceLabels)
	roleName := desired.GetName()

	r.log.V(4).Info("reconciling clusterrole resource", "name", roleName)
	fetched := &rbacv1.ClusterRole{}
	exist, err := r.Exists(r.ctx, client.ObjectKeyFromObject(desired), fetched)
	if err != nil {
		return FromClientError(err, "failed to check %s clusterrole resource already exists", roleName)
	}

	if exist && isCreate {
		r.eventRecorder.Eventf(trustmanager, corev1.EventTypeWarning, "ResourceAlreadyExists", "%s clusterrole resource already exists, maybe from previous installation", roleName)
	}
	if exist && hasObjectChanged(desired, fetched) {
		r.log.V(1).Info("clusterrole has been modified, updating to desired state", "name", roleName)
		if err := r.UpdateWithRetry(r.ctx, desired); err != nil {
			return FromClientError(err, "failed to update %s clusterrole resource", roleName)
		}
		r.eventRecorder.Eventf(trustmanager, corev1.EventTypeNormal, "Reconciled", "clusterrole resource %s reconciled back to desired state", roleName)
	} else {
		r.log.V(4).Info("clusterrole resource already exists and is in expected state", "name", roleName)
	}
	if !exist {
		if err := r.Create(r.ctx, desired); err != nil {
			return FromClientError(err, "failed to create %s clusterrole resource", roleName)
		}
		r.eventRecorder.Eventf(trustmanager, corev1.EventTypeNormal, "Reconciled", "clusterrole resource %s created", roleName)
	}

	return nil
}

// getClusterRoleObject loads the ClusterRole from bindata and appends dynamic rules for
// secretTargets.policy == Custom so that trust-manager can write to the authorized secrets.
func (r *Reconciler) getClusterRoleObject(trustmanager *v1alpha1.TrustManager, resourceLabels map[string]string) *rbacv1.ClusterRole {
	clusterRole := decodeClusterRoleObjBytes(assets.MustAsset(clusterRoleAssetName))
	updateResourceLabels(clusterRole, resourceLabels)

	if trustmanager.Spec.TrustManagerConfig.SecretTargets.Policy == v1alpha1.SecretTargetsPolicyCustom {
		for _, secretName := range trustmanager.Spec.TrustManagerConfig.SecretTargets.AuthorizedSecrets {
			clusterRole.Rules = append(clusterRole.Rules, rbacv1.PolicyRule{
				APIGroups:     []string{""},
				Resources:     []string{"secrets"},
				ResourceNames: []string{secretName},
				Verbs:         []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			})
		}
	}

	return clusterRole
}

func (r *Reconciler) createOrApplyClusterRoleBindings(trustmanager *v1alpha1.TrustManager, serviceAccount string, resourceLabels map[string]string, isCreate bool) error {
	desired := r.getClusterRoleBindingObject(serviceAccount, resourceLabels)
	roleBindingName := desired.GetName()

	r.log.V(4).Info("reconciling clusterrolebinding resource", "name", roleBindingName)
	fetched := &rbacv1.ClusterRoleBinding{}
	exist, err := r.Exists(r.ctx, client.ObjectKeyFromObject(desired), fetched)
	if err != nil {
		return FromClientError(err, "failed to check %s clusterrolebinding resource already exists", roleBindingName)
	}

	if exist && isCreate {
		r.eventRecorder.Eventf(trustmanager, corev1.EventTypeWarning, "ResourceAlreadyExists", "%s clusterrolebinding resource already exists, maybe from previous installation", roleBindingName)
	}
	if exist && hasObjectChanged(desired, fetched) {
		r.log.V(1).Info("clusterrolebinding has been modified, updating to desired state", "name", roleBindingName)
		if err := r.UpdateWithRetry(r.ctx, desired); err != nil {
			return FromClientError(err, "failed to update %s clusterrolebinding resource", roleBindingName)
		}
		r.eventRecorder.Eventf(trustmanager, corev1.EventTypeNormal, "Reconciled", "clusterrolebinding resource %s reconciled back to desired state", roleBindingName)
	} else {
		r.log.V(4).Info("clusterrolebinding resource already exists and is in expected state", "name", roleBindingName)
	}
	if !exist {
		if err := r.Create(r.ctx, desired); err != nil {
			return FromClientError(err, "failed to create %s clusterrolebinding resource", roleBindingName)
		}
		r.eventRecorder.Eventf(trustmanager, corev1.EventTypeNormal, "Reconciled", "clusterrolebinding resource %s created", roleBindingName)
	}

	return nil
}

func (r *Reconciler) getClusterRoleBindingObject(serviceAccount string, resourceLabels map[string]string) *rbacv1.ClusterRoleBinding {
	clusterRoleBinding := decodeClusterRoleBindingObjBytes(assets.MustAsset(clusterRoleBindingAssetName))
	updateResourceLabels(clusterRoleBinding, resourceLabels)
	updateServiceAccountNamespaceInRBACBindingObject[*rbacv1.ClusterRoleBinding](clusterRoleBinding, serviceAccount, certManagerNamespace)
	return clusterRoleBinding
}

func (r *Reconciler) createOrApplyRoles(trustmanager *v1alpha1.TrustManager, trustNamespace string, resourceLabels map[string]string, isCreate bool) error {
	desired := r.getRoleObject(trustNamespace, resourceLabels)
	roleName := fmt.Sprintf("%s/%s", desired.GetNamespace(), desired.GetName())

	r.log.V(4).Info("reconciling role resource", "name", roleName)
	fetched := &rbacv1.Role{}
	exist, err := r.Exists(r.ctx, client.ObjectKeyFromObject(desired), fetched)
	if err != nil {
		return FromClientError(err, "failed to check %s role resource already exists", roleName)
	}

	if exist && isCreate {
		r.eventRecorder.Eventf(trustmanager, corev1.EventTypeWarning, "ResourceAlreadyExists", "%s role resource already exists, maybe from previous installation", roleName)
	}
	if exist && hasObjectChanged(desired, fetched) {
		r.log.V(1).Info("role has been modified, updating to desired state", "name", roleName)
		if err := r.UpdateWithRetry(r.ctx, desired); err != nil {
			return FromClientError(err, "failed to update %s role resource", roleName)
		}
		r.eventRecorder.Eventf(trustmanager, corev1.EventTypeNormal, "Reconciled", "role resource %s reconciled back to desired state", roleName)
	} else {
		r.log.V(4).Info("role resource already exists and is in expected state", "name", roleName)
	}
	if !exist {
		if err := r.Create(r.ctx, desired); err != nil {
			return FromClientError(err, "failed to create %s role resource", roleName)
		}
		r.eventRecorder.Eventf(trustmanager, corev1.EventTypeNormal, "Reconciled", "role resource %s created", roleName)
	}

	return nil
}

func (r *Reconciler) getRoleObject(trustNamespace string, resourceLabels map[string]string) *rbacv1.Role {
	role := decodeRoleObjBytes(assets.MustAsset(roleAssetName))
	updateNamespace(role, trustNamespace)
	updateResourceLabels(role, resourceLabels)
	return role
}

func (r *Reconciler) createOrApplyRoleBindings(trustmanager *v1alpha1.TrustManager, serviceAccount, trustNamespace string, resourceLabels map[string]string, isCreate bool) error {
	desired := r.getRoleBindingObject(serviceAccount, trustNamespace, resourceLabels)
	roleBindingName := fmt.Sprintf("%s/%s", desired.GetNamespace(), desired.GetName())

	r.log.V(4).Info("reconciling rolebinding resource", "name", roleBindingName)
	fetched := &rbacv1.RoleBinding{}
	exist, err := r.Exists(r.ctx, client.ObjectKeyFromObject(desired), fetched)
	if err != nil {
		return FromClientError(err, "failed to check %s rolebinding resource already exists", roleBindingName)
	}

	if exist && isCreate {
		r.eventRecorder.Eventf(trustmanager, corev1.EventTypeWarning, "ResourceAlreadyExists", "%s rolebinding resource already exists, maybe from previous installation", roleBindingName)
	}
	if exist && hasObjectChanged(desired, fetched) {
		r.log.V(1).Info("rolebinding has been modified, updating to desired state", "name", roleBindingName)
		if err := r.UpdateWithRetry(r.ctx, desired); err != nil {
			return FromClientError(err, "failed to update %s rolebinding resource", roleBindingName)
		}
		r.eventRecorder.Eventf(trustmanager, corev1.EventTypeNormal, "Reconciled", "rolebinding resource %s reconciled back to desired state", roleBindingName)
	} else {
		r.log.V(4).Info("rolebinding resource already exists and is in expected state", "name", roleBindingName)
	}
	if !exist {
		if err := r.Create(r.ctx, desired); err != nil {
			return FromClientError(err, "failed to create %s rolebinding resource", roleBindingName)
		}
		r.eventRecorder.Eventf(trustmanager, corev1.EventTypeNormal, "Reconciled", "rolebinding resource %s created", roleBindingName)
	}

	return nil
}

func (r *Reconciler) getRoleBindingObject(serviceAccount, trustNamespace string, resourceLabels map[string]string) *rbacv1.RoleBinding {
	roleBinding := decodeRoleBindingObjBytes(assets.MustAsset(roleBindingAssetName))
	updateNamespace(roleBinding, trustNamespace)
	updateResourceLabels(roleBinding, resourceLabels)
	updateServiceAccountNamespaceInRBACBindingObject[*rbacv1.RoleBinding](roleBinding, serviceAccount, certManagerNamespace)
	return roleBinding
}

func (r *Reconciler) createOrApplyLeaderElectionRole(trustmanager *v1alpha1.TrustManager, resourceLabels map[string]string, isCreate bool) error {
	desired := r.getLeaderElectionRoleObject(resourceLabels)
	roleName := fmt.Sprintf("%s/%s", desired.GetNamespace(), desired.GetName())

	r.log.V(4).Info("reconciling leader election role resource", "name", roleName)
	fetched := &rbacv1.Role{}
	exist, err := r.Exists(r.ctx, client.ObjectKeyFromObject(desired), fetched)
	if err != nil {
		return FromClientError(err, "failed to check %s role resource already exists", roleName)
	}

	if exist && isCreate {
		r.eventRecorder.Eventf(trustmanager, corev1.EventTypeWarning, "ResourceAlreadyExists", "%s role resource already exists, maybe from previous installation", roleName)
	}
	if exist && hasObjectChanged(desired, fetched) {
		r.log.V(1).Info("leader election role has been modified, updating to desired state", "name", roleName)
		if err := r.UpdateWithRetry(r.ctx, desired); err != nil {
			return FromClientError(err, "failed to update %s role resource", roleName)
		}
		r.eventRecorder.Eventf(trustmanager, corev1.EventTypeNormal, "Reconciled", "role resource %s reconciled back to desired state", roleName)
	} else {
		r.log.V(4).Info("leader election role resource already exists and is in expected state", "name", roleName)
	}
	if !exist {
		if err := r.Create(r.ctx, desired); err != nil {
			return FromClientError(err, "failed to create %s role resource", roleName)
		}
		r.eventRecorder.Eventf(trustmanager, corev1.EventTypeNormal, "Reconciled", "role resource %s created", roleName)
	}

	return nil
}

func (r *Reconciler) getLeaderElectionRoleObject(resourceLabels map[string]string) *rbacv1.Role {
	role := decodeRoleObjBytes(assets.MustAsset(leaderElectionRoleAssetName))
	updateResourceLabels(role, resourceLabels)
	return role
}

func (r *Reconciler) createOrApplyLeaderElectionRoleBinding(trustmanager *v1alpha1.TrustManager, serviceAccount string, resourceLabels map[string]string, isCreate bool) error {
	desired := r.getLeaderElectionRoleBindingObject(serviceAccount, resourceLabels)
	roleBindingName := fmt.Sprintf("%s/%s", desired.GetNamespace(), desired.GetName())

	r.log.V(4).Info("reconciling leader election rolebinding resource", "name", roleBindingName)
	fetched := &rbacv1.RoleBinding{}
	exist, err := r.Exists(r.ctx, client.ObjectKeyFromObject(desired), fetched)
	if err != nil {
		return FromClientError(err, "failed to check %s rolebinding resource already exists", roleBindingName)
	}

	if exist && isCreate {
		r.eventRecorder.Eventf(trustmanager, corev1.EventTypeWarning, "ResourceAlreadyExists", "%s rolebinding resource already exists, maybe from previous installation", roleBindingName)
	}
	if exist && hasObjectChanged(desired, fetched) {
		r.log.V(1).Info("leader election rolebinding has been modified, updating to desired state", "name", roleBindingName)
		if err := r.UpdateWithRetry(r.ctx, desired); err != nil {
			return FromClientError(err, "failed to update %s rolebinding resource", roleBindingName)
		}
		r.eventRecorder.Eventf(trustmanager, corev1.EventTypeNormal, "Reconciled", "rolebinding resource %s reconciled back to desired state", roleBindingName)
	} else {
		r.log.V(4).Info("leader election rolebinding resource already exists and is in expected state", "name", roleBindingName)
	}
	if !exist {
		if err := r.Create(r.ctx, desired); err != nil {
			return FromClientError(err, "failed to create %s rolebinding resource", roleBindingName)
		}
		r.eventRecorder.Eventf(trustmanager, corev1.EventTypeNormal, "Reconciled", "rolebinding resource %s created", roleBindingName)
	}

	return nil
}

func (r *Reconciler) getLeaderElectionRoleBindingObject(serviceAccount string, resourceLabels map[string]string) *rbacv1.RoleBinding {
	roleBinding := decodeRoleBindingObjBytes(assets.MustAsset(leaderElectionRoleBindingAssetName))
	updateResourceLabels(roleBinding, resourceLabels)
	updateServiceAccountNamespaceInRBACBindingObject[*rbacv1.RoleBinding](roleBinding, serviceAccount, certManagerNamespace)
	return roleBinding
}
