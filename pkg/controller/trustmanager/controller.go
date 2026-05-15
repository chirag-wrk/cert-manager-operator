package trustmanager

import (
	"context"
	"fmt"
	"reflect"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/go-logr/logr"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"

	v1alpha1 "github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
)

var (
	requestEnqueueLabelKey   = "app"
	requestEnqueueLabelValue = trustManagerCommonName
)

// Reconciler reconciles a TrustManager object.
type Reconciler struct {
	ctrlClient

	ctx               context.Context
	eventRecorder     record.EventRecorder
	log               logr.Logger
	scheme            *runtime.Scheme
	operatorNamespace string
}

// +kubebuilder:rbac:groups=operator.openshift.io,resources=trustmanagers,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=operator.openshift.io,resources=trustmanagers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=operator.openshift.io,resources=trustmanagers/finalizers,verbs=update

// NewCacheBuilder returns a cache builder function configured with label selectors
// for managed resources. This function is used by the manager to create its cache
// to ensure the reconciler reads from the same cache that the controller's watches use.
func NewCacheBuilder(config *rest.Config, opts cache.Options) (cache.Cache, error) {
	managedResourceLabelReq, err := labels.NewRequirement(requestEnqueueLabelKey, selection.Equals, []string{requestEnqueueLabelValue})
	if err != nil {
		return nil, fmt.Errorf("invalid cache label requirement for %q: %w", requestEnqueueLabelKey, err)
	}
	managedResourceLabelReqSelector := labels.NewSelector().Add(*managedResourceLabelReq)

	opts.ByObject = map[client.Object]cache.ByObject{
		&v1alpha1.TrustManager{}: {},
		&certmanagerv1.Certificate{}: {
			Label: managedResourceLabelReqSelector,
		},
		&certmanagerv1.Issuer{}: {
			Label: managedResourceLabelReqSelector,
		},
		&appsv1.Deployment{}: {
			Label: managedResourceLabelReqSelector,
		},
		&rbacv1.ClusterRole{}: {
			Label: managedResourceLabelReqSelector,
		},
		&rbacv1.ClusterRoleBinding{}: {
			Label: managedResourceLabelReqSelector,
		},
		&rbacv1.Role{}: {
			Label: managedResourceLabelReqSelector,
		},
		&rbacv1.RoleBinding{}: {
			Label: managedResourceLabelReqSelector,
		},
		&corev1.Service{}: {
			Label: managedResourceLabelReqSelector,
		},
		&corev1.ServiceAccount{}: {
			Label: managedResourceLabelReqSelector,
		},
		&corev1.ConfigMap{}: {
			Label: managedResourceLabelReqSelector,
		},
		&admissionregistrationv1.ValidatingWebhookConfiguration{}: {
			Label: managedResourceLabelReqSelector,
		},
	}

	return cache.New(config, opts)
}

// New returns a new Reconciler instance.
func New(mgr ctrl.Manager, operatorNamespace string) (*Reconciler, error) {
	c, err := NewClient(mgr)
	if err != nil {
		return nil, err
	}
	return &Reconciler{
		ctrlClient:        c,
		ctx:               context.Background(),
		eventRecorder:     mgr.GetEventRecorderFor(ControllerName),
		log:               ctrl.Log.WithName(ControllerName),
		scheme:            mgr.GetScheme(),
		operatorNamespace: operatorNamespace,
	}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	mapFunc := func(ctx context.Context, obj client.Object) []reconcile.Request {
		r.log.V(4).Info("received reconcile event", "object", fmt.Sprintf("%T", obj), "name", obj.GetName(), "namespace", obj.GetNamespace())

		if obj.GetLabels() != nil && obj.GetLabels()[requestEnqueueLabelKey] == requestEnqueueLabelValue {
			return []reconcile.Request{
				{NamespacedName: types.NamespacedName{Name: trustManagerObjectName}},
			}
		}

		r.log.V(4).Info("object not of interest, ignoring reconcile event", "object", fmt.Sprintf("%T", obj), "name", obj.GetName())
		return []reconcile.Request{}
	}

	controllerManagedResources := predicate.NewPredicateFuncs(func(object client.Object) bool {
		return object.GetLabels() != nil && object.GetLabels()[requestEnqueueLabelKey] == requestEnqueueLabelValue
	})

	withIgnoreStatusUpdatePredicates := builder.WithPredicates(predicate.GenerationChangedPredicate{}, controllerManagedResources)
	controllerManagedResourcePredicates := builder.WithPredicates(controllerManagedResources)

	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.TrustManager{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Named(ControllerName).
		Watches(&certmanagerv1.Certificate{}, handler.EnqueueRequestsFromMapFunc(mapFunc), withIgnoreStatusUpdatePredicates).
		Watches(&certmanagerv1.Issuer{}, handler.EnqueueRequestsFromMapFunc(mapFunc), controllerManagedResourcePredicates).
		Watches(&appsv1.Deployment{}, handler.EnqueueRequestsFromMapFunc(mapFunc), withIgnoreStatusUpdatePredicates).
		Watches(&rbacv1.ClusterRole{}, handler.EnqueueRequestsFromMapFunc(mapFunc), controllerManagedResourcePredicates).
		Watches(&rbacv1.ClusterRoleBinding{}, handler.EnqueueRequestsFromMapFunc(mapFunc), controllerManagedResourcePredicates).
		Watches(&rbacv1.Role{}, handler.EnqueueRequestsFromMapFunc(mapFunc), controllerManagedResourcePredicates).
		Watches(&rbacv1.RoleBinding{}, handler.EnqueueRequestsFromMapFunc(mapFunc), controllerManagedResourcePredicates).
		Watches(&corev1.Service{}, handler.EnqueueRequestsFromMapFunc(mapFunc), controllerManagedResourcePredicates).
		Watches(&corev1.ServiceAccount{}, handler.EnqueueRequestsFromMapFunc(mapFunc), controllerManagedResourcePredicates).
		Watches(&corev1.ConfigMap{}, handler.EnqueueRequestsFromMapFunc(mapFunc), controllerManagedResourcePredicates).
		Watches(&admissionregistrationv1.ValidatingWebhookConfiguration{}, handler.EnqueueRequestsFromMapFunc(mapFunc), controllerManagedResourcePredicates).
		Complete(r)
}

// Reconcile compares the state specified by the TrustManager object against the actual cluster state,
// and makes the cluster state reflect the state specified by the user.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.log.V(1).Info("reconciling", "request", req)

	trustmanager := &v1alpha1.TrustManager{}
	if err := r.Get(ctx, req.NamespacedName, trustmanager); err != nil {
		if errors.IsNotFound(err) {
			r.log.V(1).Info("trustmanager.operator.openshift.io object not found, skipping reconciliation", "request", req)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to fetch trustmanager.operator.openshift.io %q during reconciliation: %w", req.NamespacedName, err)
	}

	// Only process the singleton CR
	if trustmanager.GetName() != trustManagerObjectName {
		r.log.V(1).Info("ignoring non-singleton trustmanager resource", "name", trustmanager.GetName())
		return ctrl.Result{}, nil
	}

	if !trustmanager.DeletionTimestamp.IsZero() {
		r.log.V(1).Info("trustmanager.operator.openshift.io is marked for deletion", "name", req.NamespacedName)

		if err := r.removeFinalizer(ctx, trustmanager, finalizer); err != nil {
			return ctrl.Result{}, err
		}

		r.log.V(1).Info("removed finalizer, cleanup complete", "name", req.NamespacedName)
		return ctrl.Result{}, nil
	}

	if err := r.addFinalizer(ctx, trustmanager); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update %q trustmanager.operator.openshift.io with finalizers: %w", req.NamespacedName, err)
	}

	return r.processReconcileRequest(trustmanager, req.NamespacedName)
}

func (r *Reconciler) processReconcileRequest(trustmanager *v1alpha1.TrustManager, req types.NamespacedName) (ctrl.Result, error) {
	isCreate := reflect.DeepEqual(trustmanager.Status, v1alpha1.TrustManagerStatus{})

	var errUpdate error
	if err := r.reconcileTrustManagerDeployment(trustmanager, isCreate); err != nil {
		r.log.Error(err, "failed to reconcile TrustManager deployment", "name", req)
		if IsIrrecoverableError(err) {
			degradedChanged := trustmanager.Status.SetCondition(v1alpha1.Degraded, metav1.ConditionTrue, v1alpha1.ReasonFailed, fmt.Sprintf("reconciliation failed with irrecoverable error not retrying: %v", err))
			readyChanged := trustmanager.Status.SetCondition(v1alpha1.Ready, metav1.ConditionFalse, v1alpha1.ReasonReady, "")

			if degradedChanged || readyChanged {
				errUpdate = r.updateCondition(trustmanager, nil)
			}
			return ctrl.Result{}, errUpdate
		}

		degradedChanged := trustmanager.Status.SetCondition(v1alpha1.Degraded, metav1.ConditionFalse, v1alpha1.ReasonReady, "")
		readyChanged := trustmanager.Status.SetCondition(v1alpha1.Ready, metav1.ConditionFalse, v1alpha1.ReasonInProgress, fmt.Sprintf("reconciliation failed, retrying: %v", err))

		if degradedChanged || readyChanged {
			errUpdate = r.updateCondition(trustmanager, err)
		}
		if errUpdate != nil {
			return ctrl.Result{}, errUpdate
		}
		return ctrl.Result{RequeueAfter: defaultRequeueTime}, nil
	}

	degradedChanged := trustmanager.Status.SetCondition(v1alpha1.Degraded, metav1.ConditionFalse, v1alpha1.ReasonReady, "")
	readyChanged := trustmanager.Status.SetCondition(v1alpha1.Ready, metav1.ConditionTrue, v1alpha1.ReasonReady, "reconciliation successful")

	if degradedChanged || readyChanged {
		errUpdate = r.updateCondition(trustmanager, nil)
	}
	return ctrl.Result{}, errUpdate
}
