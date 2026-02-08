#!/usr/bin/env python3
"""Format Trivy config JSON output thành table dễ đọc (giống Jenkins report)."""
import json
import sys

def main():
    if len(sys.argv) < 2:
        print("Usage: format_trivy_config.py <trivy.json>", file=sys.stderr)
        sys.exit(1)

    path = sys.argv[1]
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Error reading {path}: {e}", file=sys.stderr)
        sys.exit(1)

    results = data.get("Results", [])
    if not results and isinstance(data, list):
        results = data
    if not results:
        print("No misconfigurations found.")
        return

    # Path + tên file: harbor.yaml -> apps/playground/harbor/harbor.yaml
    def target_to_path(target: str) -> str:
        if not target:
            return "unknown"
        parts = target.split("/")
        filename = parts[-1]  # harbor.yaml
        base = filename.replace(".yaml", "").replace(".yml", "")
        return f"apps/playground/{base}/{filename}"

    rows = []
    for r in results:
        target = r.get("Target", "")
        file_path = target_to_path(target)
        for m in r.get("Misconfigurations", []):
            mid = m.get("ID", "")
            severity = m.get("Severity", "")
            title = (m.get("Title") or m.get("Message", ""))[:80]
            if len((m.get("Title") or m.get("Message", ""))) > 80:
                title += "..."
            meta = m.get("CauseMetadata", {}) or {}
            start = meta.get("StartLine", "")
            end = meta.get("EndLine", "")
            loc = f"{start}-{end}" if start and end else str(start) if start else ""
            rows.append((file_path, mid, severity, loc, title))

    if not rows:
        print("No misconfigurations found.")
        return

    # Table format (giống Jenkins)
    col_widths = [
        max(25, max(len(r[0]) for r in rows)),
        max(12, max(len(r[1]) for r in rows)),
        max(8, max(len(r[2]) for r in rows)),
        max(10, max(len(r[3]) for r in rows)),
        max(60, min(80, max(len(r[4]) for r in rows))),
    ]
    w0, w1, w2, w3, w4 = col_widths

    sep = "+" + "-" * (w0 + 2) + "+" + "-" * (w1 + 2) + "+" + "-" * (w2 + 2) + "+" + "-" * (w3 + 2) + "+" + "-" * (w4 + 2) + "+"
    header = f"| {'File (k8s_manifest)'[:w0].ljust(w0)} | {'ID'.ljust(w1)} | {'Severity'.ljust(w2)} | {'Lines'.ljust(w3)} | {'Title'.ljust(w4)} |"

    lines = [
        "Report Summary (Misconfigurations)",
        sep,
        header,
        sep,
    ]
    for r in rows:
        line = f"| {r[0][:w0].ljust(w0)} | {r[1].ljust(w1)} | {r[2].ljust(w2)} | {str(r[3]).ljust(w3)} | {r[4][:w4].ljust(w4)} |"
        lines.append(line)
    lines.append(sep)
    lines.append("")
    lines.append(f"Total: {len(rows)} findings")

    print("\n".join(lines))

if __name__ == "__main__":
    main()
