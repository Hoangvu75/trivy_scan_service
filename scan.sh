#!/bin/sh
# Chỉ quét cluster K8s trực tiếp (trivy k8s) — misconfig + vuln, đầy đủ.
# Cần chạy trong cluster với ServiceAccount có quyền đọc (RBAC).
set -e

WORK_DIR="${WORK_DIR:-/tmp/scan}"
mkdir -p "$WORK_DIR"

echo "=== K8s Cluster Trivy Scan (live) ==="
echo "Running Trivy k8s (misconfig + vuln, full scan)..."
TRIVY_K8S="$WORK_DIR/trivy-k8s.json"

# misconfig + vuln (quét cả image), exit-code 0 để có finding vẫn không thoát lỗi
if trivy k8s --scanners misconfig,vuln --exit-code 0 -f json -o "$TRIVY_K8S" 2>&1; then
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
