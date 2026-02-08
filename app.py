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


def run_scan(manifest_repo=None, git_token=None):
    """Run trivy scan and return (output, exit_code)."""
    env = os.environ.copy()
    env["MANIFEST_REPO"] = manifest_repo or MANIFEST_REPO
    env["GIT_TOKEN"] = git_token or GIT_TOKEN
    env["WORK_DIR"] = tempfile.mkdtemp()

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


def post_to_discord(content: str, webhook_url: str):
    """Post content to Discord webhook. Returns success bool."""
    if not webhook_url:
        return False

    if len(content) > 1900:
        content = content[:1900] + "\n... (truncated)"

    payload = {"content": f"```\n{content}\n```"}

    req = urllib.request.Request(
        webhook_url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status in (200, 204)
    except Exception:
        return False


def run_scan_and_notify(webhook_url, manifest_repo=None, git_token=None):
    """Run scan in background and post to Discord."""
    print("[scan] Started", flush=True)
    try:
        output, exit_code = run_scan(manifest_repo, git_token)
        header = "=== K8s Manifest Trivy Config Scan ===\n"
        full = header + (output or "No output")
        ok = post_to_discord(full, webhook_url)
        print(f"[scan] Done (exit={exit_code}, discord={'ok' if ok else 'fail'})", flush=True)
    except Exception as e:
        print(f"[scan] Error: {e}", flush=True)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/scan", methods=["POST", "GET"])
def scan():
    """Trigger scan. Optionally: body { discord_webhook?, manifest_repo?, git_token? }."""
    webhook = DISCORD_WEBHOOK
    manifest_repo = MANIFEST_REPO
    git_token = GIT_TOKEN

    if request.is_json:
        data = request.get_json() or {}
        webhook = data.get("discord_webhook") or webhook
        manifest_repo = data.get("manifest_repo") or manifest_repo
        git_token = data.get("git_token") or git_token

    if not webhook:
        return jsonify({"error": "No discord_webhook in body or DISCORD_WEBHOOK_URL env"}), 400

    # Run scan async so we return 200 quickly (GitHub/n8n webhooks often timeout)
    threading.Thread(
        target=run_scan_and_notify,
        kwargs={"webhook_url": webhook, "manifest_repo": manifest_repo, "git_token": git_token},
    ).start()

    return jsonify({"status": "scan_started", "message": "Results will be posted to Discord"}), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
