"""
SentinelAegis-X - Architectural Foundation Visual Designer
Generates high-resolution cyber defense schematic (foundation_design.jpg)
depicting dataflow, human gatekeeper, threat triage, Discord alerts, and fightback engine.
"""

import os
from PIL import Image, ImageDraw, ImageFont


def draw_schematic():
    width = 1920
    height = 1080
    img = Image.new("RGB", (width, height), color=(10, 14, 23))
    draw = ImageDraw.Draw(img)

    # Background Cyber Grid
    grid_color = (18, 26, 43)
    for x in range(0, width, 40):
        draw.line([(x, 0), (x, height)], fill=grid_color, width=1)
    for y in range(0, height, 40):
        draw.line([(0, y), (width, y)], fill=grid_color, width=1)

    # Gradient glow or header accent
    draw.rectangle([(0, 0), (width, 80)], fill=(17, 25, 39))
    draw.line([(0, 80), (width, 80)], fill=(0, 242, 254), width=2)

    # Try default fonts or system font
    try:
        font_title = ImageFont.truetype("arialbd.ttf", 32)
        font_header = ImageFont.truetype("arialbd.ttf", 20)
        font_body = ImageFont.truetype("arial.ttf", 15)
        font_mono = ImageFont.truetype("consola.ttf", 14)
    except Exception:
        font_title = font_header = font_body = font_mono = ImageFont.load_default()

    # Title
    draw.text((40, 24), "SENTINELAECIS-X // CORE DEFENSE ARCHITECTURE & DATAFLOW SCHEMATIC", fill=(0, 242, 254), font=font_title)
    draw.text((1500, 30), "STATUS: HUMAN_GATE_ACTIVE", fill=(255, 170, 0), font=font_header)

    # Block drawing helper
    def draw_node(x, y, w, h, title, subtitle, items, border_col, fill_col=(18, 26, 43)):
        # Glow border
        draw.rounded_rectangle([(x-2, y-2), (x+w+2, y+h+2)], radius=10, outline=border_col, width=2)
        draw.rounded_rectangle([(x, y), (x+w, y+h)], radius=8, fill=fill_col)
        # Header strip
        draw.rectangle([(x+1, y+1), (x+w-1, y+36)], fill=(25, 35, 55))
        draw.line([(x+1, y+36), (x+w-1, y+36)], fill=border_col, width=1)
        draw.text((x+15, y+8), title, fill=(255, 255, 255), font=font_header)
        draw.text((x+15, y+45), subtitle, fill=(148, 163, 184), font=font_body)
        
        curr_y = y + 75
        for item in items:
            draw.text((x+20, curr_y), f"• {item}", fill=(226, 232, 240), font=font_mono)
            curr_y += 24

    # 1. Ingress & Attack Vectors (Left column)
    draw_node(
        60, 130, 380, 260,
        "[01] INGRESS & ATTACK SENSORS",
        "Continuous Multi-Vector Telemetry",
        [
            "Filesystem Watcher (Downloads/Temp/Startup)",
            "Network Sockets (Reverse Shells, C2 Beacon)",
            "Wi-Fi Sentinel (Rogue AP, ARP MITM Spoofing)",
            "Phishing Engine (.eml Header, SPF/DKIM)",
            "RAT & Trojan Persistence Scanner"
        ],
        (0, 242, 254)
    )

    # 2. Static & Heuristic Triage (Middle-Left)
    draw_node(
        500, 130, 420, 260,
        "[02] ANALYSIS & TRIAGE ENGINE",
        "Deep Static Inspection (Zero Execution)",
        [
            "Shannon Entropy Parser (Packed Code Detection)",
            "PE/ELF Header Dissection & Section Map",
            "Win32 API Import Analysis (VirtualAlloc/Inject)",
            "Dynamic 0-100 Threat Scoring Algorithm",
            "Adaptive Machine-Learned Signature Cache"
        ],
        (0, 255, 153)
    )

    # 3. Internet Threat Intelligence (Bottom-Left)
    draw_node(
        60, 430, 380, 250,
        "[03] GLOBAL INTEL FEED HARVESTER",
        "Internet-Wide Threat Learning",
        [
            "URLhaus Real-Time Phishing/Malware Feeds",
            "MalwareBazaar In-The-Wild SHA256 Hashes",
            "Continuous Threat Pattern Assimilation",
            "Local Knowledge Base Cache Serialization",
            "Auto-Extracted Defensive YARA Signatures"
        ],
        (157, 78, 221)
    )

    # 4. HUMAN-IN-THE-LOOP APPROVAL GATE (Centerpiece - Orange Warning)
    draw_node(
        500, 430, 420, 250,
        "[04] HUMAN-IN-THE-LOOP GATEKEEPER",
        "ZERO AUTONOMOUS ACTION ENFORCEMENT",
        [
            "System Lock: Absolutely No Destruction Unapproved",
            "Incident ID Registration (INC-XXXXXX)",
            "Multi-Factor Webhook / UI Alert Dispatch",
            "Awaits Operator Command (KILL / QUARANTINE)",
            "Full Cryptographic Audit Log of Authorization"
        ],
        (255, 170, 0),
        fill_col=(30, 25, 15)
    )

    # 5. Discord C2 & Telemetry (Top-Right)
    draw_node(
        980, 130, 420, 260,
        "[05] DISCORD C2 & ALERTING SYSTEM",
        "Real-Time Mobile & Desktop Telemetry",
        [
            "Rich Cyber Embeds (Color-coded Threat Score)",
            "Target File Path, PID, Hashes & Attack Indicators",
            "Interactive Operator Bot Approval Commands",
            "1-Click Local Webhook Integration",
            "Remediation Execution Confirmation Dispatch"
        ],
        (88, 101, 242)
    )

    # 6. Linux & Windows Fightback Engine (Bottom-Right)
    draw_node(
        980, 430, 420, 250,
        "[06] REMEDIATION & FIGHTBACK SYSTEM",
        "Active Containment Upon Human Approval",
        [
            "Linux iptables Inbound/Outbound IP Drop",
            "Windows Netsh Advanced Firewall Isolation",
            "Recursive Process Tree Termination (taskkill/SIGKILL)",
            "Zero-Out File Scrubbing & Unlink",
            "Encrypted XOR-Vault File Quarantine Isolation"
        ],
        (255, 51, 102)
    )

    # 7. Modern UI / UX Web Cockpit (Spanning Right-Most column)
    draw_node(
        1460, 130, 400, 550,
        "[07] OPERATOR COCKPIT UI/UX",
        "Glassmorphism Dark Control Center",
        [
            "Real-Time Incident HUD & Radar Cards",
            "1-Click Instant Action Buttons:",
            "  -> [KILL PROCESS TREE]",
            "  -> [QUARANTINE ENCRYPT]",
            "  -> [DISMISS / SAFE]",
            "Drag & Drop Static File Sandbox Inspection",
            "Live Threat Intel Synchronization Trigger",
            "Zero-Latency WebSocket & REST API Integration",
            "Tailwind + JetBrains Cyber Aesthetics"
        ],
        (0, 242, 254)
    )

    # 8. Encrypted Vault (Bottom Wide banner)
    draw_node(
        60, 720, 1800, 190,
        "[08] SECURE QUARANTINE VAULT & AUDIT INFRASTRUCTURE",
        "Air-Gapped In-Memory Scrambling & Evidence Preservation",
        [
            "Payloads XOR-Scrambled (Key 0xA5) into isolated ./vault/*.vault binaries preventing accidental host execution",
            "Sidecar metadata (.meta.json) logs original path, SHA-256, timestamps, detection telemetry, and operator identity",
            "Git repository synchronizer automatically stages and commits defensive codebases while excluding active vaults"
        ],
        (0, 255, 153)
    )

    # Draw Connecting Vectors / Flow lines
    def draw_arrow(p1, p2, col=(0, 242, 254)):
        draw.line([p1, p2], fill=col, width=3)

    # Arrows between blocks
    draw_arrow((440, 260), (500, 260))  # Sensor -> Triage
    draw_arrow((710, 390), (710, 430))  # Triage -> Human Gate
    draw_arrow((440, 555), (500, 555))  # Threat Intel -> Human Gate
    draw_arrow((920, 555), (980, 555), col=(255, 170, 0))  # Human Gate -> Fightback
    draw_arrow((920, 260), (980, 260), col=(88, 101, 242))  # Triage/Gate -> Discord
    draw_arrow((1400, 555), (1460, 555), col=(0, 242, 254))  # Fightback -> UI

    # Footer banner
    draw.rectangle([(0, 1020), (width, height)], fill=(17, 25, 39))
    draw.line([(0, 1020), (width, 1020)], fill=(0, 242, 254), width=1)
    draw.text((60, 1040), "SENTINELAEGIS-X // OFFENSIVE DEFENSE & INCIDENT RESPONSE PLATFORM // ZERO AUTONOMOUS DESTRUCTION ASSURANCE", fill=(148, 163, 184), font=font_mono)

    out_path = "foundation_design.jpg"
    img.save(out_path, "JPEG", quality=95)
    print(f"Generated schematic visual: {os.path.abspath(out_path)}")


if __name__ == "__main__":
    draw_schematic()
