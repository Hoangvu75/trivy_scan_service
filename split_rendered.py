#!/usr/bin/env python3
"""Tách file YAML đã render (nhiều document ---) thành từng file theo Kind và metadata.name.
   Đọc từ rendered/*.yaml, ghi ra rendered_split/env/app/Kind-name.yaml để Trivy báo đúng tên resource.
"""
import re
import sys
from pathlib import Path


def extract_kind_name(doc: str) -> tuple[str, str] | None:
    kind_m = re.search(r"^kind:\s*(\w+)", doc, re.MULTILINE | re.IGNORECASE)
    name_m = re.search(r"^\s*name:\s*(\S+)", doc, re.MULTILINE)
    if kind_m and name_m:
        kind = kind_m.group(1)
        name = name_m.group(1).strip('"\'')
        # Tên file an toàn
        safe = re.sub(r"[^\w.-]", "-", name).strip("-") or "unnamed"
        return (kind, safe)
    return None


def main():
    if len(sys.argv) < 3:
        print("Usage: split_rendered.py <rendered_dir> <output_dir>", file=sys.stderr)
        sys.exit(1)
    rendered_dir = Path(sys.argv[1])
    output_dir = Path(sys.argv[2])
    output_dir.mkdir(parents=True, exist_ok=True)

    for path in sorted(rendered_dir.glob("*.yaml")):
        stem = path.stem  # playground-harbor
        if "-" not in stem:
            continue
        env, app = stem.split("-", 1)
        app_dir = output_dir / env / app
        app_dir.mkdir(parents=True, exist_ok=True)
        content = path.read_text(encoding="utf-8", errors="replace")
        docs = [d.strip() for d in content.split("\n---\n") if d.strip()]
        seen = set()
        for doc in docs:
            kn = extract_kind_name(doc)
            if not kn:
                continue
            kind, name = kn
            filename = f"{kind}-{name}.yaml"
            if filename in seen:
                idx = 1
                while f"{kind}-{name}-{idx}.yaml" in seen:
                    idx += 1
                filename = f"{kind}-{name}-{idx}.yaml"
            seen.add(filename)
            (app_dir / filename).write_text(doc, encoding="utf-8")


if __name__ == "__main__":
    main()
