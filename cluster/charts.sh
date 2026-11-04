#!/bin/bash
# Install popular open-source Helm charts into the APA cluster, with their real RBAC (service
# accounts, ClusterRoles, bindings), so the graph also holds production-like workloads next to
# KubeHound's vulnerable fixtures. Versions are pinned (latest on 2 Nov 2026).
set -euo pipefail

HELM=${HELM:-$(cygpath "$LOCALAPPDATA")/Microsoft/WinGet/Packages/Helm.Helm_Microsoft.Winget.Source_8wekyb3d8bbwe/windows-amd64/helm.exe}

"$HELM" repo add ingress-nginx https://kubernetes.github.io/ingress-nginx >/dev/null
"$HELM" repo add jetstack https://charts.jetstack.io >/dev/null
"$HELM" repo add argo https://argoproj.github.io/argo-helm >/dev/null
"$HELM" repo add prometheus-community https://prometheus-community.github.io/helm-charts >/dev/null
"$HELM" repo update >/dev/null

# no cloud load balancer in kind: NodePort
"$HELM" upgrade --install ingress-nginx ingress-nginx/ingress-nginx --version 4.15.1 \
  -n ingress-nginx --create-namespace --set controller.service.type=NodePort
"$HELM" upgrade --install cert-manager jetstack/cert-manager --version v1.21.3 \
  -n cert-manager --create-namespace --set crds.enabled=true
"$HELM" upgrade --install argocd argo/argo-cd --version 10.11.6 -n argocd --create-namespace
# short retention keeps Prometheus small; everything else at chart defaults
"$HELM" upgrade --install monitoring prometheus-community/kube-prometheus-stack --version 92.17.0 \
  -n monitoring --create-namespace --set prometheus.prometheusSpec.retention=2h
