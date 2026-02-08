#!/usr/bin/env python3
"""Format Trivy k8s (cluster scan) JSON output thành table.
   Cấu trúc: Misconfigurations[] -> Namespace, Kind, Name, Results[].Misconfigurations[].
"""
import json
import sys


def main():
    if len(sys.argv) < 2:
        print("Usage: format_trivy_k8s.py <trivy-k8s.json>", file=sys.stderr)
        sys.exit(1)

    path = sys.argv[1]
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Error reading {path}: {e}", file=sys.stderr)
        sys.exit(1)

    resources = data.get("Misconfigurations", [])
    rows = []
    for resource in resources:
        ns = resource.get("Namespace", "")
        kind = resource.get("Kind", "")
        name = resource.get("Name", "")
        resource_path = f"{ns}/{kind}/{name}"
        for result in resource.get("Results", []):
            for m in result.get("Misconfigurations", []):
                mid = m.get("ID", "")
                severity = m.get("Severity", "")
                title = (m.get("Title") or m.get("Message", ""))[:80]
                if len((m.get("Title") or m.get("Message", ""))) > 80:
                    title += "..."
                meta = m.get("IacMetadata", {}) or m.get("CauseMetadata", {}) or {}
                start = meta.get("StartLine", "")
                end = meta.get("EndLine", "")
                loc = f"{start}-{end}" if start and end else str(start) if start else ""
                rows.append((resource_path, mid, severity, loc, title))

    # Luôn in tóm tắt: đã quét bao nhiêu resource, bao nhiêu findings (để so sánh với scan repo)
    kind_counts = {}
    for r in resources:
        k = r.get("Kind", "?")
        kind_counts[k] = kind_counts.get(k, 0) + 1
    summary = ", ".join(f"{k}:{v}" for k, v in sorted(kind_counts.items()))
    print(f"Resources scanned: {len(resources)} ({summary})")
    print(f"Misconfigurations found: {len(rows)}")

    if not rows:
        print("No misconfigurations found (cluster objects may pass checks or differ from repo YAML).")
        return

    col_widths = [
        max(35, max(len(r[0]) for r in rows)),
        max(12, max(len(r[1]) for r in rows)),
        max(8, max(len(r[2]) for r in rows)),
        max(10, max(len(r[3]) for r in rows)),
        max(60, min(80, max(len(r[4]) for r in rows))),
    ]
    w0, w1, w2, w3, w4 = col_widths

    sep = "+" + "-" * (w0 + 2) + "+" + "-" * (w1 + 2) + "+" + "-" * (w2 + 2) + "+" + "-" * (w3 + 2) + "+" + "-" * (w4 + 2) + "+"
    header = f"| {'Resource (namespace/kind/name)'[:w0].ljust(w0)} | {'ID'.ljust(w1)} | {'Severity'.ljust(w2)} | {'Lines'.ljust(w3)} | {'Title'.ljust(w4)} |"

    cluster_name = data.get("ClusterName", "cluster")
    lines = [
        f"Report Summary (Cluster: {cluster_name}, Misconfigurations)",
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
