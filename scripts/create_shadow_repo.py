"""
SentinelAegis-X - Shadow Repository Builder (Client Showcase Edition)
Generates a sanitized, client-safe public distribution:
- Strips active private Discord webhooks & credentials
- Preserves full UI/UX dashboard, static analyzer, and architecture schematics
- Safe to publish publicly for client demonstrations without leaking internal telemetry
"""

import os
import shutil
import json


def build_shadow_repo(dist_dir="./dist/sentinel-shadow-client"):
    if os.path.exists(dist_dir):
        shutil.rmtree(dist_dir)
    os.makedirs(dist_dir, exist_ok=True)

    # Directories to copy
    for folder in ["config", "core", "ui", "scripts"]:
        src = folder
        dst = os.path.join(dist_dir, folder)
        shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))

    # Empty safe directories
    os.makedirs(os.path.join(dist_dir, "vault"), exist_ok=True)
    with open(os.path.join(dist_dir, "vault", ".gitkeep"), "w") as f:
        f.write("# Isolated vault directory\n")

    os.makedirs(os.path.join(dist_dir, "intel_cache"), exist_ok=True)
    with open(os.path.join(dist_dir, "intel_cache", ".gitkeep"), "w") as f:
        f.write("# Local threat cache\n")

    # Files to copy
    for file in ["main.py", "requirements.txt", "foundation_design.jpg", "ui_design_preview.jpg", "live_chrome_test.jpg", ".gitignore"]:
        if os.path.exists(file):
            shutil.copy(file, os.path.join(dist_dir, file))

    # Sanitize settings.json for public client distribution
    shadow_settings_path = os.path.join(dist_dir, "config", "settings.json")
    with open(shadow_settings_path, "r", encoding="utf-8") as f:
        settings = json.load(f)

    # Replace live private credentials with client demo placeholders
    settings["discord"]["webhook_url"] = "https://discord.com/api/webhooks/YOUR_PUBLIC_DEMO_WEBHOOK"
    settings["discord"]["bot_token"] = "YOUR_DISCORD_BOT_TOKEN_OPTIONAL"
    
    # Redact personal target emails in public repo
    if "monitoring" in settings and "email" in settings["monitoring"]:
        settings["monitoring"]["email"]["target_accounts"] = [
            {"email": "client-demo-1@example.com", "provider": "gmail"},
            {"email": "client-demo-2@example.com", "provider": "gmail"}
        ]

    with open(shadow_settings_path, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2)

    # Write Client Showcase README
    client_readme = (
        "# 🛡️ SentinelAegis-X (Client Showcase Edition)\n\n"
        "**Autonomous Cyber Defense & Static Malware Triage Platform**\n\n"
        "This is the client-facing demonstration repository featuring:\n"
        "- Real-time Shannon Entropy & PE/ELF binary dissection\n"
        "- Zero-Autonomous Destruction Human Gatekeeper\n"
        "- Cross-Platform Linux & Windows Fightback Architecture\n"
        "- Cyberpunk glassmorphism Web Cockpit (`http://127.0.0.1:8800`)\n"
        "- Threat Intelligence Sync (URLhaus & MalwareBazaar)\n\n"
        "### Architecture & Previews\n"
        "See `foundation_design.jpg` and `ui_design_preview.jpg` for complete system designs.\n"
    )
    with open(os.path.join(dist_dir, "README.md"), "w", encoding="utf-8") as f:
        f.write(client_readme)

    print(f"[+] Client Shadow Repository generated at: {os.path.abspath(dist_dir)}")
    return dist_dir


if __name__ == "__main__":
    build_shadow_repo()
