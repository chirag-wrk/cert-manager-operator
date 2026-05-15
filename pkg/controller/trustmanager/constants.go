package trustmanager

import (
	"os"
	"time"
)

const (
	// certManagerNamespace is the namespace where trust-manager and its core resources are deployed.
	certManagerNamespace = "cert-manager"

	// trustManagerCommonName is the name commonly used for naming resources.
	trustManagerCommonName = "trust-manager"

	// ControllerName is the name of the controller used in logs and events.
	ControllerName = trustManagerCommonName + "-controller"

	// finalizer name for trustmanager.operator.openshift.io resource.
	finalizer = "trustmanager.openshift.operator.io/" + ControllerName

	// defaultRequeueTime is the default reconcile requeue time.
	defaultRequeueTime = time.Second * 30

	// trustManagerObjectName is the name of the TrustManager resource created by user.
	// TrustManager CRD enforces name to be `cluster`.
	trustManagerObjectName = "cluster"

	// trustManagerContainerName is the name of the container created for trust-manager.
	trustManagerContainerName = trustManagerCommonName

	// trustManagerImageNameEnvVarName is the environment variable key name
	// containing the image name of trust-manager as value.
	trustManagerImageNameEnvVarName = "RELATED_IMAGE_TRUST_MANAGER"

	// trustManagerImageVersionEnvVarName is the environment variable key name
	// containing the image version of trust-manager as value.
	trustManagerImageVersionEnvVarName = "TRUST_MANAGER_OPERAND_IMAGE_VERSION"

	// defaultCAPackageHashAnnotation is the annotation key on the Deployment used to
	// track the SHA256 hash of the default CA package ConfigMap data. A change triggers
	// a rolling restart.
	defaultCAPackageHashAnnotation = "operator.openshift.io/default-ca-package-hash"

	// trustedCABundleConfigMapName is the name of the ConfigMap in the operator namespace
	// that contains the cluster-wide trusted CA bundle.
	trustedCABundleConfigMapName = "cert-manager-operator-trusted-ca-bundle"

	// defaultCAPackageConfigMapName is the name of the ConfigMap created in the
	// cert-manager namespace and mounted into the trust-manager Deployment.
	defaultCAPackageConfigMapName = "trust-manager-default-ca-package"
)

var (
	controllerDefaultResourceLabels = map[string]string{
		"app":                          trustManagerCommonName,
		"app.kubernetes.io/name":       trustManagerCommonName,
		"app.kubernetes.io/instance":   trustManagerCommonName,
		"app.kubernetes.io/version":    os.Getenv(trustManagerImageVersionEnvVarName),
		"app.kubernetes.io/managed-by": "cert-manager-operator",
		"app.kubernetes.io/part-of":    "cert-manager-operator",
	}
)

// asset names are the files present in the bindata/trust-manager/ dir. Which are then loaded
// and made available by the pkg/operator/assets package.
const (
	serviceAccountAssetName            = "trust-manager/resources/trust-manager-serviceaccount.yaml"
	clusterRoleAssetName               = "trust-manager/resources/trust-manager-clusterrole.yaml"
	clusterRoleBindingAssetName        = "trust-manager/resources/trust-manager-clusterrolebinding.yaml"
	roleAssetName                      = "trust-manager/resources/trust-manager-role.yaml"
	roleBindingAssetName               = "trust-manager/resources/trust-manager-rolebinding.yaml"
	leaderElectionRoleAssetName        = "trust-manager/resources/trust-manager-leaderelection-role.yaml"
	leaderElectionRoleBindingAssetName = "trust-manager/resources/trust-manager-leaderelection-rolebinding.yaml"
	deploymentAssetName                = "trust-manager/resources/trust-manager-deployment.yaml"
	serviceAssetName                   = "trust-manager/resources/trust-manager-service.yaml"
	metricsServiceAssetName            = "trust-manager/resources/trust-manager-metrics-service.yaml"
	issuerAssetName                    = "trust-manager/resources/trust-manager-issuer.yaml"
	certificateAssetName               = "trust-manager/resources/trust-manager-certificate.yaml"
	validatingWebhookConfigAssetName   = "trust-manager/resources/trust-manager-validatingwebhookconfiguration.yaml"
)
