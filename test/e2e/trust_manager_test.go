//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/test/library"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	trustManagerDeploymentName = "cert-manager-trust-manager"
	trustManagerSAName         = "cert-manager-trust-manager"
	trustManagerCRName         = "cluster"
	trustManagerClusterRole    = "cert-manager-trust-manager"
	trustManagerTimeout        = 5 * time.Minute
)

var _ = Describe("TrustManager", Ordered, Label("Feature:TrustManager"), func() {
	ctx := context.TODO()
	var tmClient ctrlclient.Client

	BeforeAll(func() {
		s := runtime.NewScheme()
		Expect(v1alpha1.AddToScheme(s)).To(Succeed())
		var err error
		tmClient, err = ctrlclient.New(cfg, ctrlclient.Options{Scheme: s})
		Expect(err).NotTo(HaveOccurred())
	})

	Describe("TrustManager feature gate enforcement", Ordered, func() {
		It("should not run trust-manager when FeatureTrustManager gate is disabled", func() {
			Skip("requires operator restart without FeatureTrustManager=true; validated via operator startup configuration")
		})
	})

	Describe("Basic trust-manager deployment", Ordered, func() {
		BeforeAll(func() {
			By("creating TrustManager CR named 'cluster'")
			_, err := library.CreateTrustManager(ctx, tmClient, v1alpha1.TrustManagerSpec{
				TrustManagerConfig: v1alpha1.TrustManagerConfig{},
			})
			Expect(err).NotTo(HaveOccurred())
		})

		AfterAll(func() {
			By("deleting TrustManager CR")
			_ = library.DeleteTrustManager(ctx, tmClient)
		})

		It("should deploy trust-manager operand in the cert-manager namespace", func() {
			By("polling until trust-manager deployment is available")
			Expect(pollTillDeploymentAvailable(ctx, k8sClientSet, operandNamespace, trustManagerDeploymentName)).To(Succeed())
		})

		It("should report Ready=True condition on the TrustManager CR", func() {
			By("waiting for TrustManager CR Ready condition")
			Expect(library.WaitForTrustManagerReady(ctx, tmClient, trustManagerTimeout)).To(Succeed())
		})
	})

	Describe("MicroShift gate", Ordered, func() {
		It("should allow trust-manager when featuregates.config.openshift.io CRD is absent", func() {
			Skip("MicroShift environment required: featuregates.config.openshift.io CRD must be absent")
		})
	})

	Describe("Trust namespace configuration", Ordered, func() {
		const customTrustNamespace = "cert-manager"

		BeforeAll(func() {
			By("creating TrustManager CR with explicit trustNamespace")
			_, err := library.CreateTrustManager(ctx, tmClient, v1alpha1.TrustManagerSpec{
				TrustManagerConfig: v1alpha1.TrustManagerConfig{
					TrustNamespace: customTrustNamespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			By("waiting for TrustManager to be Ready")
			Expect(library.WaitForTrustManagerReady(ctx, tmClient, trustManagerTimeout)).To(Succeed())
		})

		AfterAll(func() {
			_ = library.DeleteTrustManager(ctx, tmClient)
		})

		It("should reflect the configured trustNamespace in status", func() {
			tm := &v1alpha1.TrustManager{}
			Expect(tmClient.Get(ctx, ctrlclient.ObjectKey{Name: trustManagerCRName}, tm)).To(Succeed())
			Expect(tm.Status.TrustNamespace).To(Equal(customTrustNamespace))
		})
	})

	Describe("SecretTargets configuration", Ordered, func() {
		authorizedSecrets := []string{"my-trust-bundle"}

		BeforeAll(func() {
			By("creating TrustManager CR with Custom secretTargets policy")
			_, err := library.CreateTrustManager(ctx, tmClient, v1alpha1.TrustManagerSpec{
				TrustManagerConfig: v1alpha1.TrustManagerConfig{
					SecretTargets: v1alpha1.SecretTargetsConfig{
						Policy:            v1alpha1.SecretTargetsPolicyCustom,
						AuthorizedSecrets: authorizedSecrets,
					},
				},
			})
			Expect(err).NotTo(HaveOccurred())
			By("waiting for TrustManager to be Ready")
			Expect(library.WaitForTrustManagerReady(ctx, tmClient, trustManagerTimeout)).To(Succeed())
		})

		AfterAll(func() {
			_ = library.DeleteTrustManager(ctx, tmClient)
		})

		It("should reflect Custom secretTargets policy in status", func() {
			tm := &v1alpha1.TrustManager{}
			Expect(tmClient.Get(ctx, ctrlclient.ObjectKey{Name: trustManagerCRName}, tm)).To(Succeed())
			Expect(tm.Status.SecretTargetsPolicy).To(Equal(string(v1alpha1.SecretTargetsPolicyCustom)))
		})

		It("should add authorized secret names to the trust-manager ClusterRole", func() {
			By("getting the trust-manager ClusterRole")
			cr, err := k8sClientSet.RbacV1().ClusterRoles().Get(ctx, trustManagerClusterRole, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("verifying authorized secret is listed in ClusterRole resourceNames")
			var found bool
			for _, rule := range cr.Rules {
				for _, resource := range rule.Resources {
					if resource == "secrets" {
						for _, name := range rule.ResourceNames {
							if name == authorizedSecrets[0] {
								found = true
							}
						}
					}
				}
			}
			Expect(found).To(BeTrue(), fmt.Sprintf("ClusterRole %q should list %q in secrets resourceNames", trustManagerClusterRole, authorizedSecrets[0]))
		})
	})

	Describe("DefaultCAPackage integration", Ordered, func() {
		BeforeAll(func() {
			By("creating TrustManager CR with defaultCAPackage enabled")
			_, err := library.CreateTrustManager(ctx, tmClient, v1alpha1.TrustManagerSpec{
				TrustManagerConfig: v1alpha1.TrustManagerConfig{
					DefaultCAPackage: v1alpha1.DefaultCAPackageConfig{
						Policy: v1alpha1.DefaultCAPackagePolicyEnabled,
					},
				},
			})
			Expect(err).NotTo(HaveOccurred())
			By("waiting for TrustManager to be Ready")
			Expect(library.WaitForTrustManagerReady(ctx, tmClient, trustManagerTimeout)).To(Succeed())
		})

		AfterAll(func() {
			_ = library.DeleteTrustManager(ctx, tmClient)
		})

		It("should reflect Enabled defaultCAPackage policy in status", func() {
			tm := &v1alpha1.TrustManager{}
			Expect(tmClient.Get(ctx, ctrlclient.ObjectKey{Name: trustManagerCRName}, tm)).To(Succeed())
			Expect(tm.Status.DefaultCAPackagePolicy).To(Equal(string(v1alpha1.DefaultCAPackagePolicyEnabled)))
		})

		It("should mount the default CA package volume in the trust-manager deployment", func() {
			By("getting the trust-manager deployment")
			dep, err := k8sClientSet.AppsV1().Deployments(operandNamespace).Get(ctx, trustManagerDeploymentName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("verifying trust-manager-default-ca-package volume is present")
			var found bool
			for _, vol := range dep.Spec.Template.Spec.Volumes {
				if vol.Name == "trust-manager-default-ca-package" {
					found = true
					break
				}
			}
			Expect(found).To(BeTrue(), "trust-manager deployment should have trust-manager-default-ca-package volume")
		})
	})

	Describe("FilterExpiredCertificates", Ordered, func() {
		BeforeAll(func() {
			By("creating TrustManager CR with filterExpiredCertificates enabled")
			_, err := library.CreateTrustManager(ctx, tmClient, v1alpha1.TrustManagerSpec{
				TrustManagerConfig: v1alpha1.TrustManagerConfig{
					FilterExpiredCertificates: v1alpha1.FilterExpiredCertificatesPolicyEnabled,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			By("waiting for TrustManager to be Ready")
			Expect(library.WaitForTrustManagerReady(ctx, tmClient, trustManagerTimeout)).To(Succeed())
		})

		AfterAll(func() {
			_ = library.DeleteTrustManager(ctx, tmClient)
		})

		It("should reflect FilterExpiredCertificates policy in status", func() {
			tm := &v1alpha1.TrustManager{}
			Expect(tmClient.Get(ctx, ctrlclient.ObjectKey{Name: trustManagerCRName}, tm)).To(Succeed())
			Expect(tm.Status.FilterExpiredCertificatesPolicy).To(Equal(string(v1alpha1.FilterExpiredCertificatesPolicyEnabled)))
		})

		It("should pass --filter-expired-certificates flag to trust-manager", func() {
			By("getting the trust-manager deployment")
			dep, err := k8sClientSet.AppsV1().Deployments(operandNamespace).Get(ctx, trustManagerDeploymentName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(dep.Spec.Template.Spec.Containers).NotTo(BeEmpty())

			By("verifying --filter-expired-certificates flag is present in container args")
			var found bool
			for _, arg := range dep.Spec.Template.Spec.Containers[0].Args {
				if arg == "--filter-expired-certificates" {
					found = true
					break
				}
			}
			Expect(found).To(BeTrue(), "trust-manager deployment should run with --filter-expired-certificates flag")
		})
	})

	Describe("Resource labeling", Ordered, func() {
		BeforeAll(func() {
			By("creating TrustManager CR")
			_, err := library.CreateTrustManager(ctx, tmClient, v1alpha1.TrustManagerSpec{
				TrustManagerConfig: v1alpha1.TrustManagerConfig{},
			})
			Expect(err).NotTo(HaveOccurred())
			By("waiting for TrustManager to be Ready")
			Expect(library.WaitForTrustManagerReady(ctx, tmClient, trustManagerTimeout)).To(Succeed())
		})

		AfterAll(func() {
			_ = library.DeleteTrustManager(ctx, tmClient)
		})

		It("should label trust-manager deployment with app.kubernetes.io/name", func() {
			dep, err := k8sClientSet.AppsV1().Deployments(operandNamespace).Get(ctx, trustManagerDeploymentName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(dep.Labels).To(HaveKeyWithValue("app.kubernetes.io/name", "cert-manager-trust-manager"))
		})

		It("should label trust-manager deployment with app.kubernetes.io/managed-by", func() {
			dep, err := k8sClientSet.AppsV1().Deployments(operandNamespace).Get(ctx, trustManagerDeploymentName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(dep.Labels).To(HaveKeyWithValue("app.kubernetes.io/managed-by", "cert-manager-operator"))
		})

		It("should label trust-manager service account with standard labels", func() {
			sa, err := k8sClientSet.CoreV1().ServiceAccounts(operandNamespace).Get(ctx, trustManagerSAName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(sa.Labels).To(HaveKeyWithValue("app.kubernetes.io/name", "cert-manager-trust-manager"))
		})
	})

	Describe("Status conditions", Ordered, func() {
		BeforeAll(func() {
			By("creating TrustManager CR")
			_, err := library.CreateTrustManager(ctx, tmClient, v1alpha1.TrustManagerSpec{
				TrustManagerConfig: v1alpha1.TrustManagerConfig{
					TrustNamespace: "cert-manager",
				},
			})
			Expect(err).NotTo(HaveOccurred())
			By("waiting for TrustManager to be Ready")
			Expect(library.WaitForTrustManagerReady(ctx, tmClient, trustManagerTimeout)).To(Succeed())
		})

		AfterAll(func() {
			_ = library.DeleteTrustManager(ctx, tmClient)
		})

		It("should have Ready=True condition", func() {
			tm := &v1alpha1.TrustManager{}
			Expect(tmClient.Get(ctx, ctrlclient.ObjectKey{Name: trustManagerCRName}, tm)).To(Succeed())
			cond := library.GetTrustManagerCondition(tm, v1alpha1.Ready)
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionTrue))
		})

		It("should populate status.trustManagerImage", func() {
			tm := &v1alpha1.TrustManager{}
			Expect(tmClient.Get(ctx, ctrlclient.ObjectKey{Name: trustManagerCRName}, tm)).To(Succeed())
			Expect(tm.Status.TrustManagerImage).NotTo(BeEmpty())
		})

		It("should reflect trustNamespace in status", func() {
			tm := &v1alpha1.TrustManager{}
			Expect(tmClient.Get(ctx, ctrlclient.ObjectKey{Name: trustManagerCRName}, tm)).To(Succeed())
			Expect(tm.Status.TrustNamespace).To(Equal("cert-manager"))
		})
	})
})
