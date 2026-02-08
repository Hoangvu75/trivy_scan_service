#!/bin/sh
# Quét cluster K8s trực tiếp (trivy k8s). Mọi thứ chạy trong pod CronJob, không tạo namespace/Job.
# --disable-node-collector: không tạo trivy-temp + node-collector Job, chỉ đọc API và quét.
set -e

WORK_DIR="${WORK_DIR:-/tmp/scan}"
mkdir -p "$WORK_DIR"
export TRIVY_CACHE_DIR="${TRIVY_CACHE_DIR:-/tmp/trivy-cache}"
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-/tmp/trivy-cache}"
mkdir -p "$TRIVY_CACHE_DIR"

echo "=== K8s Cluster Trivy Scan (live) ==="
# TRIVY_SKIP_IMAGES=1: chỉ misconfig. Để trống: misconfig + vuln (quét image, lâu hơn).
if [ -n "$TRIVY_SKIP_IMAGES" ] && [ "$TRIVY_SKIP_IMAGES" != "0" ]; then
  echo "Running Trivy k8s (misconfig only, skip images, no node collector)..."
  TRIVY_EXTRA="--scanners misconfig --skip-images --disable-node-collector"
else
  echo "Running Trivy k8s (misconfig + vuln, no node collector)..."
  TRIVY_EXTRA="--scanners misconfig,vuln --disable-node-collector"
fi
TRIVY_K8S="$WORK_DIR/trivy-k8s.json"

if trivy k8s $TRIVY_EXTRA --exit-code 0 -f json -o "$TRIVY_K8S" 2>&1; then
  :
else
  trivy k8s --scanners misconfig --skip-images --disable-node-collector --exit-code 0 -f json -o "$TRIVY_K8S" 2>&1 || true
fi

if [ -f "$TRIVY_K8S" ]; then
  python3 /app/format_trivy_k8s.py "$TRIVY_K8S" 2>/dev/null || cat "$TRIVY_K8S"
else
  echo "Trivy k8s failed (check RBAC / cluster access)."
  exit 1
fi
