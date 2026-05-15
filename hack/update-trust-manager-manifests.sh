#!/bin/bash

set -e

source "$(dirname "${BASH_SOURCE}")/lib/init.sh"
source "$(dirname "${BASH_SOURCE}")/lib/yq.sh"

TRUST_MANAGER_VERSION=${1:-"v0.20.3"}

mkdir -p ./_output

echo "---- Downloading trust-manager manifests ${TRUST_MANAGER_VERSION} ----"

./bin/helm repo add cert-manager https://charts.jetstack.io --force-update
./bin/helm template trust-manager cert-manager/trust-manager \
    -n cert-manager --version "${TRUST_MANAGER_VERSION}" \
    --set defaultPackage.enabled=false > _output/trust-manager-manifest.yaml

echo "---- Patching manifest ----"

# remove the helm specific labels from .metadata.labels and .spec.template.metadata.labels
./bin/yq e 'del(.metadata.labels."helm.sh/chart")' -i _output/trust-manager-manifest.yaml
./bin/yq e 'del(.spec.template.metadata.labels."helm.sh/chart")' -i _output/trust-manager-manifest.yaml
./bin/yq e 'del(.spec.template.metadata.labels."app.kubernetes.io/managed-by")' -i _output/trust-manager-manifest.yaml

# update all occurrences of app.kubernetes.io/managed-by label value.
./bin/yq e \
  '(.[][] | select(has("app.kubernetes.io/managed-by"))."app.kubernetes.io/managed-by") |= "cert-manager-operator"' \
  -i _output/trust-manager-manifest.yaml

# regenerate all bindata
rm -rf bindata/trust-manager
mkdir -p bindata/trust-manager/resources

# split into individual manifest files
./bin/yq --output-format json \
    eval-all '.' -I 0 \
    _output/trust-manager-manifest.yaml | while read -r item; do

  name=$(echo "$item" | ./bin/yq eval '.metadata.name' -)
  kind=$(echo "$item" | ./bin/yq eval '.kind' - | tr '[:upper:]' '[:lower:]')

  output_file="bindata/trust-manager/resources/${name}-${kind}.yaml"

  echo "$item" | ./bin/yq eval -P > "$output_file"
  echo "$output_file"
done

# hand-craft Issuer and Certificate for webhook TLS if not produced by Helm chart
if [ ! -f "bindata/trust-manager/resources/trust-manager-issuer.yaml" ]; then
  echo "---- Generating webhook TLS Issuer ----"
  cat > bindata/trust-manager/resources/trust-manager-issuer.yaml << 'ISSUER_EOF'
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: trust-manager
  namespace: cert-manager
  labels:
    app: trust-manager
    app.kubernetes.io/name: trust-manager
    app.kubernetes.io/instance: trust-manager
    app.kubernetes.io/managed-by: cert-manager-operator
    app.kubernetes.io/part-of: cert-manager-operator
spec:
  selfSigned: {}
ISSUER_EOF
fi

if [ ! -f "bindata/trust-manager/resources/trust-manager-certificate.yaml" ]; then
  echo "---- Generating webhook TLS Certificate ----"
  cat > bindata/trust-manager/resources/trust-manager-certificate.yaml << 'CERT_EOF'
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: trust-manager
  namespace: cert-manager
  labels:
    app: trust-manager
    app.kubernetes.io/name: trust-manager
    app.kubernetes.io/instance: trust-manager
    app.kubernetes.io/managed-by: cert-manager-operator
    app.kubernetes.io/part-of: cert-manager-operator
spec:
  dnsNames:
    - trust-manager.cert-manager.svc
    - trust-manager.cert-manager.svc.cluster.local
  secretName: trust-manager-tls
  issuerRef:
    name: trust-manager
    kind: Issuer
CERT_EOF
fi

echo "---- Trust-manager manifests updated ----"
