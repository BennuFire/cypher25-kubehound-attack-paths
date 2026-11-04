#!/bin/bash
# Dump the running kind cluster, (re)build the KubeHound graph and export it to data/raw/kubehound.
# Wipes the KubeHound backend first, so the graph holds exactly one run.
# Git Bash on Windows; see README "KubeHound graph" for the one-time setup.
#
#   bash cluster/build_graph.sh                  dump + ingest + export
#   bash cluster/build_graph.sh --ingest-only    reuse the saved dump; the cluster may be stopped
#
# With ~1,600 pods running, the machine has no room left for KubeHound's backend (its graph DB
# never turns healthy). So dump first, stop the kind nodes, then run with --ingest-only.
set -euo pipefail

APA=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
KH=${KH:-$APA/../KubeHound}
export KUBECONFIG=${KUBECONFIG:-$KH/test/setup/.kube-config}
RAW=$APA/data/raw/kubehound
DIR=$RAW/kind-kubehound.test.local
KHBIN=$KH/bin/kubehound.exe

if [[ "${1:-}" != "--ingest-only" ]]; then
  rm -rf "$DIR"
  "$KHBIN" dump local -y "$RAW" 2>&1 | grep -E "ERROR|FATAL|result saved" || true
  [[ "${1:-}" == "--dump-only" ]] && exit 0
fi
DUMP=$(ls "$DIR"/*.tar.gz)
# the Windows build unpacks .tar.gz into a hard-coded /tmp: extract here and ingest the folder
rm -rf "$DIR/extracted" && mkdir -p "$DIR/extracted"
tar -xzf "$DUMP" -C "$DIR/extracted" 2>/dev/null

"$KHBIN" backend down >/dev/null 2>&1 || true
"$KHBIN" backend wipe >/dev/null 2>&1 || true
"$KHBIN" backend up 2>&1 | grep -E "ERROR|FATAL" || true
"$KHBIN" ingest local "$(cygpath -m "$DIR/extracted")" 2>&1 \
  | grep -E "ERROR|FATAL|Completed graph construction" || true
"$APA/.venv/Scripts/python" "$APA/scripts/export_kubehound.py"
