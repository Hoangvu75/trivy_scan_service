#!/bin/sh
# Scan all playground apps in k8s_manifest
set -e

WORK_DIR="${WORK_DIR:-/tmp/scan}"
MANIFEST_REPO="${MANIFEST_REPO:-https://github.com/Hoangvu75/k8s_manifest.git}"
GIT_TOKEN="${GIT_TOKEN:-}"

APPS="mbs-discord-bot n8n jenkins harbor redis argocd"

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

# Render mỗi app ra file riêng để Trivy báo app name (harbor.yaml) thay vì rendered.yaml
RENDERED_DIR="$WORK_DIR/rendered"
mkdir -p "$RENDERED_DIR"
rm -f "$RENDERED_DIR"/*.yaml 2>/dev/null || true

for app in $APPS; do
  path="apps/playground/$app"
  if [ -d "$path" ]; then
    echo "Rendering $app..."
    kubectl kustomize --enable-helm "$path" 2>/dev/null > "$RENDERED_DIR/$app.yaml" || true
  fi
done

# Scan - output JSON, format thành table qua Python
echo "Running Trivy config scan..."
TRIVY_JSON="$WORK_DIR/trivy.json"
trivy config --exit-code 0 -f json -o "$TRIVY_JSON" "$RENDERED_DIR" 2>/dev/null || trivy config -f json -o "$TRIVY_JSON" "$RENDERED_DIR" 2>/dev/null
python3 /app/format_trivy_config.py "$TRIVY_JSON" 2>/dev/null || cat "$TRIVY_JSON"
