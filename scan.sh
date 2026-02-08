#!/bin/sh
# Scan toàn bộ apps trong k8s_manifest (apps/*/ - playground, infra, prod, ...)
set -e

WORK_DIR="${WORK_DIR:-/tmp/scan}"
MANIFEST_REPO="${MANIFEST_REPO:-https://github.com/Hoangvu75/k8s_manifest.git}"
GIT_TOKEN="${GIT_TOKEN:-}"

mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

# Clone
rm -rf k8s_manifest 2>/dev/null || true
if [ -n "$GIT_TOKEN" ]; then
  REPO_URL=$(echo "$MANIFEST_REPO" | sed "s|https://|https://x-access-token:${GIT_TOKEN}@|")
else
  REPO_URL="$MANIFEST_REPO"
fi
git clone --depth 1 "$REPO_URL" k8s_manifest 2>/dev/null

cd k8s_manifest

# 1) Quét nguồn apps/ -> có tên file thật (ít findings vì đa số là values/kustomization)
echo "Running Trivy config scan (source: apps/)..."
TRIVY_SOURCE="$WORK_DIR/trivy-source.json"
trivy config --exit-code 0 -f json -o "$TRIVY_SOURCE" apps/ 2>/dev/null || trivy config -f json -o "$TRIVY_SOURCE" apps/ 2>/dev/null

# 2) Render từng app rồi quét -> đủ findings (Deployment, Pod, ...) nhưng path chỉ tới app
echo "Rendering apps and running Trivy config scan (rendered)..."
RENDERED_DIR="$WORK_DIR/rendered"
mkdir -p "$RENDERED_DIR"
rm -f "$RENDERED_DIR"/*.yaml 2>/dev/null || true
for env_dir in apps/*/; do
  [ -d "$env_dir" ] || continue
  env=$(basename "$env_dir")
  for app_dir in "$env_dir"*/; do
    [ -d "$app_dir" ] || continue
    app=$(basename "$app_dir")
    kubectl kustomize --enable-helm "$app_dir" 2>/dev/null > "$RENDERED_DIR/${env}-${app}.yaml" || true
  done
done
TRIVY_RENDERED="$WORK_DIR/trivy-rendered.json"
trivy config --exit-code 0 -f json -o "$TRIVY_RENDERED" "$RENDERED_DIR" 2>/dev/null || trivy config -f json -o "$TRIVY_RENDERED" "$RENDERED_DIR" 2>/dev/null

# 3) Gộp báo cáo: nguồn (file cụ thể) + render (đủ findings, path app)
python3 /app/format_trivy_config.py "$TRIVY_SOURCE" "$TRIVY_RENDERED" 2>/dev/null || python3 /app/format_trivy_config.py "$TRIVY_SOURCE" 2>/dev/null || cat "$TRIVY_SOURCE"
