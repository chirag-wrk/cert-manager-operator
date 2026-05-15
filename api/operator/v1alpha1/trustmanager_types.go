package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func init() {
	SchemeBuilder.Register(&TrustManager{}, &TrustManagerList{})
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true

// TrustManagerList is a list of TrustManager objects.
type TrustManagerList struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is the standard list's metadata.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata
	metav1.ListMeta `json:"metadata"`

	Items []TrustManager `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=trustmanagers,scope=Cluster,categories={cert-manager-operator,trust-manager,trustmanager}
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Message",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].message"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:metadata:labels={"app.kubernetes.io/name=trustmanager","app.kubernetes.io/part-of=cert-manager-operator"}

// TrustManager describes the configuration and information about the managed trust-manager operand.
// The name must be `cluster` to make TrustManager a singleton, that is, to allow only one instance
// of TrustManager per cluster.
//
// When a TrustManager is created, the trust-manager operand is deployed in the cert-manager namespace.
//
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'cluster'",message="TrustManager is a singleton, .metadata.name must be 'cluster'"
// +operator-sdk:csv:customresourcedefinitions:displayName="TrustManager"
type TrustManager struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is the standard object's metadata.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec is the specification of the desired behavior of the TrustManager.
	// +kubebuilder:validation:Required
	// +required
	Spec TrustManagerSpec `json:"spec"`

	// status is the most recently observed status of the TrustManager.
	// +kubebuilder:validation:Optional
	// +optional
	Status TrustManagerStatus `json:"status,omitempty"`
}

// TrustManagerSpec is the specification of the desired behavior of the TrustManager.
type TrustManagerSpec struct {
	// trustManagerConfig configures the trust-manager operand's behavior.
	// +kubebuilder:validation:Required
	// +required
	TrustManagerConfig TrustManagerConfig `json:"trustManagerConfig"`

	// controllerConfig configures the controller for setting up defaults to enable the trust-manager operand.
	// +kubebuilder:validation:Optional
	// +optional
	ControllerConfig *ControllerConfig `json:"controllerConfig,omitempty"`
}

// SecretTargetsPolicy defines the policy for trust-manager to write trust bundles to Secrets.
// +kubebuilder:validation:Enum:="Disabled";"Custom"
type SecretTargetsPolicy string

const (
	// SecretTargetsPolicyDisabled disables trust-manager writing trust bundles to Secrets.
	SecretTargetsPolicyDisabled SecretTargetsPolicy = "Disabled"

	// SecretTargetsPolicyCustom enables trust-manager to write trust bundles to specifically
	// authorized Secrets listed in authorizedSecrets.
	SecretTargetsPolicyCustom SecretTargetsPolicy = "Custom"
)

// DefaultCAPackagePolicy defines the policy for using the OpenShift CNO-injected CA bundle
// as trust-manager's default CA package.
// +kubebuilder:validation:Enum:="Enabled";"Disabled"
type DefaultCAPackagePolicy string

const (
	// DefaultCAPackagePolicyEnabled enables the OpenShift CNO-native CA bundle as
	// the trust-manager default CA package.
	DefaultCAPackagePolicyEnabled DefaultCAPackagePolicy = "Enabled"

	// DefaultCAPackagePolicyDisabled disables the OpenShift CNO-native CA bundle integration.
	DefaultCAPackagePolicyDisabled DefaultCAPackagePolicy = "Disabled"
)

// FilterExpiredCertificatesPolicy defines whether trust-manager should filter expired
// certificates from trust bundles before distributing them.
// +kubebuilder:validation:Enum:="Enabled";"Disabled"
type FilterExpiredCertificatesPolicy string

const (
	// FilterExpiredCertificatesPolicyEnabled enables filtering of expired certificates.
	FilterExpiredCertificatesPolicyEnabled FilterExpiredCertificatesPolicy = "Enabled"

	// FilterExpiredCertificatesPolicyDisabled disables filtering of expired certificates.
	FilterExpiredCertificatesPolicyDisabled FilterExpiredCertificatesPolicy = "Disabled"
)

// SecretTargetsConfig configures trust-manager's ability to write trust bundles to Secrets.
//
// +kubebuilder:validation:XValidation:rule="self.policy != 'Custom' || (has(self.authorizedSecrets) && size(self.authorizedSecrets) > 0)",message="authorizedSecrets must not be empty when policy is Custom"
// +kubebuilder:validation:XValidation:rule="self.policy == 'Custom' || !has(self.authorizedSecrets) || size(self.authorizedSecrets) == 0",message="authorizedSecrets must be empty when policy is not Custom"
type SecretTargetsConfig struct {
	// policy defines whether trust-manager may write trust bundles to Secrets.
	// Disabled disables secret targets. Custom enables writing to specifically authorized Secrets.
	// +kubebuilder:default:="Disabled"
	// +kubebuilder:validation:Required
	// +required
	Policy SecretTargetsPolicy `json:"policy"`

	// authorizedSecrets is the list of Secret names in which trust-manager may write trust bundles
	// when policy is Custom. Must be non-empty when policy is Custom.
	// This field can have a maximum of 50 entries.
	// +kubebuilder:validation:MinItems:=0
	// +kubebuilder:validation:MaxItems:=50
	// +listType=set
	// +kubebuilder:validation:Optional
	// +optional
	AuthorizedSecrets []string `json:"authorizedSecrets,omitempty"`
}

// DefaultCAPackageConfig configures the OpenShift CNO-native CA bundle as
// the trust-manager default CA package.
type DefaultCAPackageConfig struct {
	// policy defines whether the OpenShift CNO-injected CA bundle is used as
	// trust-manager's default CA package.
	// +kubebuilder:default:="Disabled"
	// +kubebuilder:validation:Required
	// +required
	Policy DefaultCAPackagePolicy `json:"policy"`
}

// TrustManagerConfig configures the trust-manager operand's behavior.
type TrustManagerConfig struct {
	// logLevel supports a value range as per [Kubernetes logging guidelines](https://github.com/kubernetes/community/blob/master/contributors/devel/sig-instrumentation/logging.md#what-method-to-use).
	// +kubebuilder:default:=1
	// +kubebuilder:validation:Minimum:=1
	// +kubebuilder:validation:Maximum:=5
	// +kubebuilder:validation:Optional
	// +optional
	LogLevel int32 `json:"logLevel,omitempty"`

	// logFormat specifies the output format for trust-manager logging.
	// Supported log formats are text and json.
	// +kubebuilder:validation:Enum:="text";"json"
	// +kubebuilder:default:="text"
	// +kubebuilder:validation:Optional
	// +optional
	LogFormat string `json:"logFormat,omitempty"`

	// trustNamespace is the namespace where trust sources (ConfigMaps and Secrets) are stored.
	// Defaults to cert-manager. This field is immutable once set.
	// This field can have a maximum of 63 characters.
	// +kubebuilder:default:="cert-manager"
	// +kubebuilder:validation:MinLength:=1
	// +kubebuilder:validation:MaxLength:=63
	// +kubebuilder:validation:XValidation:rule="oldSelf == '' || self == oldSelf",message="trustNamespace is immutable once set"
	// +kubebuilder:validation:Optional
	// +optional
	TrustNamespace string `json:"trustNamespace,omitempty"`

	// secretTargets configures trust-manager's ability to write trust bundles to Secrets.
	// +kubebuilder:validation:Optional
	// +optional
	SecretTargets SecretTargetsConfig `json:"secretTargets,omitempty"`

	// filterExpiredCertificates defines whether trust-manager should filter expired
	// certificates from trust bundles before distributing them.
	// +kubebuilder:default:="Disabled"
	// +kubebuilder:validation:Optional
	// +optional
	FilterExpiredCertificates FilterExpiredCertificatesPolicy `json:"filterExpiredCertificates,omitempty"`

	// defaultCAPackage configures the use of the OpenShift CNO-injected CA bundle
	// as trust-manager's default CA package.
	// +kubebuilder:validation:Optional
	// +optional
	DefaultCAPackage DefaultCAPackageConfig `json:"defaultCAPackage,omitempty"`

	// resources is for defining the resource requirements.
	// ref: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
	// +kubebuilder:validation:Optional
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// affinity is for setting scheduling affinity rules.
	// ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/
	// +kubebuilder:validation:Optional
	// +optional
	Affinity *corev1.Affinity `json:"affinity,omitempty"`

	// tolerations is for setting the pod tolerations.
	// This field can have a maximum of 50 entries.
	// ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/
	// +listType=atomic
	// +kubebuilder:validation:MinItems:=0
	// +kubebuilder:validation:MaxItems:=50
	// +kubebuilder:validation:Optional
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// nodeSelector is for defining the scheduling criteria using node labels.
	// This field can have a maximum of 50 entries.
	// ref: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/
	// +mapType=atomic
	// +kubebuilder:validation:MinProperties:=0
	// +kubebuilder:validation:MaxProperties:=50
	// +kubebuilder:validation:Optional
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
}

// TrustManagerStatus is the most recently observed status of the TrustManager.
type TrustManagerStatus struct {
	// conditions holds information about the current state of the trust-manager operand deployment.
	ConditionalStatus `json:",inline,omitempty"`

	// trustManagerImage is the name of the image and the tag used for deploying trust-manager.
	// +kubebuilder:validation:Optional
	// +optional
	TrustManagerImage string `json:"trustManagerImage,omitempty"`

	// trustNamespace is the namespace where trust sources are stored, as observed.
	// +kubebuilder:validation:Optional
	// +optional
	TrustNamespace string `json:"trustNamespace,omitempty"`

	// secretTargetsPolicy is the observed secret targets policy.
	// +kubebuilder:validation:Optional
	// +optional
	SecretTargetsPolicy string `json:"secretTargetsPolicy,omitempty"`

	// defaultCAPackagePolicy is the observed default CA package policy.
	// +kubebuilder:validation:Optional
	// +optional
	DefaultCAPackagePolicy string `json:"defaultCAPackagePolicy,omitempty"`

	// filterExpiredCertificatesPolicy is the observed filter-expired-certificates policy.
	// +kubebuilder:validation:Optional
	// +optional
	FilterExpiredCertificatesPolicy string `json:"filterExpiredCertificatesPolicy,omitempty"`
}
