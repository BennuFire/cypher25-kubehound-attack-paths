#!/bin/bash
# (Re)create the APA kind cluster and deploy: KubeHound's own fixtures + users (its script), the
# Helm charts (charts.sh), then the tenant copies from render_tenants.py. Git Bash on Windows.
#
#   bash cluster/create_cluster.sh [tenants] [share]      defaults: 90 0.6
set -euo pipefail

APA=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
KH=${KH:-$APA/../KubeHound}
SETUP=$KH/test/setup
TENANTS=${1:-90}
SHARE=${2:-0.6}
# kind from winget isn't on Git Bash's PATH
PATH="$PATH:$(cygpath "$LOCALAPPDATA")/Microsoft/WinGet/Packages/Kubernetes.kind_Microsoft.Winget.Source_8wekyb3d8bbwe"

set -a; source "$SETUP/.config"; set +a
export KUBECONFIG=$SETUP/$KIND_KUBECONFIG
# keep Git Bash from rewriting openssl's "/CN=user/O=group" subject into a Windows path
export MSYS2_ARG_CONV_EXCL="/CN"

kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true
kind create cluster --config "$APA/cluster/kind.yaml"
kind get kubeconfig --name "$CLUSTER_NAME" > "$KUBECONFIG"
kind get kubeconfig --internal --name "$CLUSTER_NAME" > "$SETUP/$KIND_KUBECONFIG_INTERNAL"
kubectl wait --for=condition=Ready nodes --all --timeout=300s

bash "$SETUP/manage-cluster-resources.sh" deploy > "$APA/cluster/out/kubehound-fixtures.log" 2>&1
bash "$APA/cluster/charts.sh" > "$APA/cluster/out/charts.log" 2>&1
"$APA/.venv/Scripts/python" "$APA/cluster/render_tenants.py" --tenants "$TENANTS" --share "$SHARE"
kubectl apply -f "$APA/cluster/out/tenants.yaml" > "$APA/cluster/out/tenants-apply.log"
kubectl wait --for=condition=Ready pods --all -A --timeout=900s > /dev/null || true
kubectl get pods -A --no-headers | awk '{print $4}' | sort | uniq -c
