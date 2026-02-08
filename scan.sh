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

# Render toàn bộ apps: duyệt apps/*/*, format: {env}-{app}.yaml
# Ví dụ: playground-harbor.yaml, infra-ingress-nginx.yaml, prod-api.yaml
RENDERED_DIR="$WORK_DIR/rendered"
mkdir -p "$RENDERED_DIR"
rm -f "$RENDERED_DIR"/*.yaml 2>/dev/null || true

for env_dir in apps/*/; do
  [ -d "$env_dir" ] || continue
  env=$(basename "$env_dir")
  for app_dir in "$env_dir"*/; do
    [ -d "$app_dir" ] || continue
    app=$(basename "$app_dir")
    echo "Rendering $env/$app..."
    kubectl kustomize --enable-helm "$app_dir" 2>/dev/null > "$RENDERED_DIR/${env}-${app}.yaml" || true
  done
done

# Scan - output JSON, format thành table qua Python
echo "Running Trivy config scan..."
TRIVY_JSON="$WORK_DIR/trivy.json"
trivy config --exit-code 0 -f json -o "$TRIVY_JSON" "$RENDERED_DIR" 2>/dev/null || trivy config -f json -o "$TRIVY_JSON" "$RENDERED_DIR" 2>/dev/null
python3 /app/format_trivy_config.py "$TRIVY_JSON" 2>/dev/null || cat "$TRIVY_JSON"
