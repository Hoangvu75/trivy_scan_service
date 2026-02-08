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
git clone --depth 1 "$REPO_URL" k8s_manifest

cd k8s_manifest

# Render each app and concatenate
RENDERED="/tmp/rendered.yaml"
: > "$RENDERED"

for app in $APPS; do
  path="apps/playground/$app"
  if [ -d "$path" ]; then
    echo "Rendering $app..."
    kubectl kustomize --enable-helm "$path" 2>/dev/null >> "$RENDERED" || true
    echo "---" >> "$RENDERED"
  fi
done

# Scan - báo cáo đầy đủ, không tóm tắt (-q bỏ để có full output)
echo "Running Trivy config scan..."
trivy config --exit-code 0 -f table "$RENDERED" 2>&1 || trivy config -f table "$RENDERED" 2>&1
