#!/bin/sh
# Scan: manifest (từ repo) hoặc cluster (trực tiếp K8s).
#   SCAN_TARGET=cluster  -> trivy k8s (cần KUBECONFIG / in-cluster)
#   SCAN_TARGET=manifest (mặc định) -> clone repo, render, trivy config
set -e

WORK_DIR="${WORK_DIR:-/tmp/scan}"
SCAN_TARGET="${SCAN_TARGET:-manifest}"
MANIFEST_REPO="${MANIFEST_REPO:-https://github.com/Hoangvu75/k8s_manifest.git}"
GIT_TOKEN="${GIT_TOKEN:-}"

mkdir -p "$WORK_DIR"

# --- Chế độ: quét cluster trực tiếp (trivy k8s) ---
if [ "$SCAN_TARGET" = "cluster" ]; then
  echo "=== K8s Cluster Trivy Scan (live) ==="
  echo "Running Trivy k8s (misconfig only, skip image scan)..."
  TRIVY_K8S="$WORK_DIR/trivy-k8s.json"
  trivy k8s --scanners misconfig --skip-images --exit-code 0 -f json -o "$TRIVY_K8S" 2>/dev/null || \
  trivy k8s --scanners misconfig --skip-images -f json -o "$TRIVY_K8S" 2>/dev/null || true
  if [ -f "$TRIVY_K8S" ]; then
    python3 /app/format_trivy_k8s.py "$TRIVY_K8S" 2>/dev/null || cat "$TRIVY_K8S"
  else
    echo "Trivy k8s failed (check KUBECONFIG / cluster access)."
  fi
  exit 0
fi

# --- Chế độ mặc định: quét manifest từ repo ---
echo "=== K8s Manifest Trivy Config Scan ==="
rm -rf k8s_manifest 2>/dev/null || true
if [ -n "$GIT_TOKEN" ]; then
  REPO_URL=$(echo "$MANIFEST_REPO" | sed "s|https://|https://x-access-token:${GIT_TOKEN}@|")
else
  REPO_URL="$MANIFEST_REPO"
fi
git clone --depth 1 "$REPO_URL" k8s_manifest 2>/dev/null

cd k8s_manifest

# 1) Quét nguồn apps/
echo "Running Trivy config scan (source: apps/)..."
TRIVY_SOURCE="$WORK_DIR/trivy-source.json"
trivy config --exit-code 0 -f json -o "$TRIVY_SOURCE" apps/ 2>/dev/null || trivy config -f json -o "$TRIVY_SOURCE" apps/ 2>/dev/null

# 2) Render từng app, tách resource, quét
echo "Rendering apps, splitting by resource, running Trivy config scan (rendered)..."
RENDERED_DIR="$WORK_DIR/rendered"
RENDERED_SPLIT="$WORK_DIR/rendered_split"
mkdir -p "$RENDERED_DIR"
rm -f "$RENDERED_DIR"/*.yaml 2>/dev/null || true
rm -rf "$RENDERED_SPLIT" 2>/dev/null || true
for env_dir in apps/*/; do
  [ -d "$env_dir" ] || continue
  env=$(basename "$env_dir")
  for app_dir in "$env_dir"*/; do
    [ -d "$app_dir" ] || continue
    app=$(basename "$app_dir")
    kubectl kustomize --enable-helm "$app_dir" 2>/dev/null > "$RENDERED_DIR/${env}-${app}.yaml" || true
  done
done
python3 /app/split_rendered.py "$RENDERED_DIR" "$RENDERED_SPLIT" 2>/dev/null || true
TRIVY_RENDERED="$WORK_DIR/trivy-rendered.json"
trivy config --exit-code 0 -f json -o "$TRIVY_RENDERED" "$RENDERED_SPLIT" 2>/dev/null || trivy config -f json -o "$TRIVY_RENDERED" "$RENDERED_DIR" 2>/dev/null

# 3) Gộp báo cáo
python3 /app/format_trivy_config.py "$TRIVY_SOURCE" "$TRIVY_RENDERED" 2>/dev/null || python3 /app/format_trivy_config.py "$TRIVY_SOURCE" 2>/dev/null || cat "$TRIVY_SOURCE"
