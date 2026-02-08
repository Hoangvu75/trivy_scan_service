#!/usr/bin/env python3
"""Trivy K8s manifest scan service - HTTP /scan endpoint, posts results to Discord."""
import os
import subprocess
import tempfile
import urllib.request
import urllib.error
import json
import threading

try:
    from flask import Flask, request, jsonify
except ImportError:
    print("Install flask: pip install flask")
    raise

app = Flask(__name__)

DISCORD_WEBHOOK = os.environ.get("DISCORD_WEBHOOK_URL", "")
MANIFEST_REPO = os.environ.get("MANIFEST_REPO", "https://github.com/Hoangvu75/k8s_manifest.git")
GIT_TOKEN = os.environ.get("GIT_TOKEN", "")


def run_scan(manifest_repo=None, git_token=None, scan_target=None):
    """Run trivy scan and return (output, exit_code).
    scan_target: 'cluster' = trivy k8s (live cluster), 'manifest' or None = repo manifest."""
    env = os.environ.copy()
    env["MANIFEST_REPO"] = manifest_repo or MANIFEST_REPO
    env["GIT_TOKEN"] = git_token or GIT_TOKEN
    env["WORK_DIR"] = tempfile.mkdtemp()
    if scan_target in ("cluster", "manifest"):
        env["SCAN_TARGET"] = scan_target

    try:
        result = subprocess.run(
            ["/app/scan.sh"],
            capture_output=True,
            text=True,
            timeout=300,
            env=env,
            cwd="/app",
        )
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        return (stdout + stderr).strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "Scan timed out after 5 minutes", 1
    except Exception as e:
        return str(e), 1


def _post_json(url: str, payload: dict) -> bool:
    """POST JSON to URL. Returns success bool."""
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status in (200, 204)
    except urllib.error.HTTPError as e:
        print(f"[post] HTTP {e.code}: {e.read().decode()[:200]}", flush=True)
        return False
    except Exception as e:
        print(f"[post] Error: {e}", flush=True)
        return False


def post_to_discord(content: str, webhook_url: str) -> bool:
    """Post content to Discord webhook."""
    if not webhook_url:
        print("[discord] No webhook URL", flush=True)
        return False
    if len(content) > 1900:
        content = content[:1900] + "\n... (truncated)"
    return _post_json(webhook_url, {"content": f"```\n{content}\n```"})


def run_scan_and_notify(webhook_url=None, callback_url=None, manifest_repo=None, git_token=None, scan_target=None):
    """Run scan in background. Post to callback_url (n8n) or Discord."""
    print("[scan] Started", flush=True)
    try:
        output, exit_code = run_scan(manifest_repo, git_token, scan_target)
        header = "=== K8s Cluster Trivy Scan ===\n" if scan_target == "cluster" else "=== K8s Manifest Trivy Config Scan ===\n"
        if exit_code != 0:
            header = f"[SCAN FAILED exit={exit_code}]\n" + header
        full = header + (output or "No output")

        if callback_url:
            payload = {"content": full}
            if DISCORD_WEBHOOK:
                payload["discord_webhook"] = DISCORD_WEBHOOK
            ok = _post_json(callback_url, payload)
            print(f"[scan] Done (exit={exit_code}, callback={'ok' if ok else 'fail'})", flush=True)
        elif webhook_url:
            ok = post_to_discord(full, webhook_url)
            print(f"[scan] Done (exit={exit_code}, discord={'ok' if ok else 'fail'})", flush=True)
        else:
            print(f"[scan] Done (exit={exit_code}, no destination)", flush=True)
    except Exception as e:
        print(f"[scan] Error: {e}", flush=True)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/scan", methods=["POST", "GET"])
def scan():
    """Trigger scan. Body: { callback_url? | discord_webhook?, manifest_repo?, git_token?, scan_target? }.
    scan_target: 'cluster' = scan live K8s cluster (trivy k8s), 'manifest' = scan repo (default).
    callback_url: n8n webhook - trivy-scan POST kết quả vào đây, n8n gửi tiếp lên Discord."""
    webhook = DISCORD_WEBHOOK
    callback_url = None
    manifest_repo = MANIFEST_REPO
    git_token = GIT_TOKEN

    scan_target = None
    if request.is_json:
        data = request.get_json() or {}
        callback_url = data.get("callback_url")
        webhook = data.get("discord_webhook") or webhook
        manifest_repo = data.get("manifest_repo") or manifest_repo
        git_token = data.get("git_token") or git_token
        scan_target = data.get("scan_target")

    if not callback_url and not webhook:
        return jsonify({"error": "Need callback_url or discord_webhook/DISCORD_WEBHOOK_URL"}), 400

    threading.Thread(
        target=run_scan_and_notify,
        kwargs={
            "webhook_url": webhook if not callback_url else None,
            "callback_url": callback_url,
            "manifest_repo": manifest_repo,
            "git_token": git_token,
            "scan_target": scan_target,
        },
    ).start()

    return jsonify({"status": "scan_started", "message": "Results will be posted to callback/Discord"}), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
