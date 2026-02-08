#!/bin/sh
# Chỉ quét cluster K8s trực tiếp (trivy k8s) — misconfig + vuln, đầy đủ.
# Cần chạy trong cluster với ServiceAccount có quyền đọc (RBAC).
set -e

WORK_DIR="${WORK_DIR:-/tmp/scan}"
mkdir -p "$WORK_DIR"
# Trivy cache (container root read-only, dùng /tmp)
export TRIVY_CACHE_DIR="${TRIVY_CACHE_DIR:-/tmp/trivy-cache}"
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-/tmp/trivy-cache}"
mkdir -p "$TRIVY_CACHE_DIR"

# Dọn namespace tạm từ lần chạy trước (tránh "job already exists" / "being terminated")
kubectl delete namespace trivy-temp --ignore-not-found=true --timeout=15s 2>/dev/null || true
# Chờ namespace xóa hẳn (Terminating có thể mất vài giây)
n=0
while kubectl get namespace trivy-temp 2>/dev/null && [ "$n" -lt 45 ]; do
  sleep 1
  n=$((n + 1))
done

echo "=== K8s Cluster Trivy Scan (live) ==="
# TRIVY_SKIP_IMAGES=1: chỉ misconfig (~1-2 phút). Để trống: misconfig + vuln (~10-15 phút).
if [ -n "$TRIVY_SKIP_IMAGES" ] && [ "$TRIVY_SKIP_IMAGES" != "0" ]; then
  echo "Running Trivy k8s (misconfig only, skip images)..."
  TRIVY_EXTRA="--scanners misconfig --skip-images"
else
  echo "Running Trivy k8s (misconfig + vuln, full scan)..."
  TRIVY_EXTRA="--scanners misconfig,vuln"
fi
TRIVY_K8S="$WORK_DIR/trivy-k8s.json"

if trivy k8s $TRIVY_EXTRA --exit-code 0 -f json -o "$TRIVY_K8S" 2>&1; then
  :
else
  # Fallback: chỉ misconfig nếu vuln quá nặng hoặc lỗi
  trivy k8s --scanners misconfig --skip-images --exit-code 0 -f json -o "$TRIVY_K8S" 2>&1 || true
fi

if [ -f "$TRIVY_K8S" ]; then
  python3 /app/format_trivy_k8s.py "$TRIVY_K8S" 2>/dev/null || cat "$TRIVY_K8S"
else
  echo "Trivy k8s failed (check RBAC / cluster access)."
  exit 1
fi
