#!/bin/bash
cd "$(dirname "${BASH_SOURCE[0]}")"
set -euo pipefail

log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') $1 ${@:2}"
}

log "[INFO] Applying OpenShift GitOps operator subscription manifests..."
oc apply -k openshift-gitops-operator

log "[INFO] Waiting for the OpenShift GitOps Operator to be available..."
until oc wait --for=condition=Available --timeout=300s deployment/openshift-gitops-operator-controller-manager -n openshift-gitops-operator >/dev/null 2>&1; do
  log "[INFO] Waiting..."
  sleep 10
done
log "[INFO] OpenShift GitOps Operator is now available."

log "[INFO] Applying OpenShift GitOps instance cluster-gitops manifests..."
oc apply -k cluster-gitops

log "[INFO] Waiting for deployment/cluster-gitops-server to be created..."
until oc get deployment cluster-gitops-server -n cluster-gitops >/dev/null 2>&1; do
  log "[INFO] Still waiting for deployment/cluster-gitops-server to be created..."
  sleep 10
done

# Verify ArgoCD is running
log "[INFO] Waiting for deployment/cluster-gitops-server to be ready..."
oc wait --for=condition=Available --timeout=300s deployment/cluster-gitops-server -n cluster-gitops
log "[INFO] OpenShift GitOps successfully installed in cluster-gitops."

ARGOCD_ROUTE=$(oc get route cluster-gitops-server -n cluster-gitops -o jsonpath='{.spec.host}')
log "[INFO] Cluster Argo CD is accessible at: https://$ARGOCD_ROUTE"