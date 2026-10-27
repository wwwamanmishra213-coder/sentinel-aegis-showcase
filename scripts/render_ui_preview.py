"""
SentinelAegis-X - High-Fidelity UI/UX Dashboard Mockup Generator
Renders a pixel-perfect dark cyberpunk dashboard preview (ui_design_preview.jpg)
showing the Operator HUD, Incident Cards, Approval Buttons, and Live Threat Metrics.
"""

import os
from PIL import Image, ImageDraw, ImageFont


def render_ui_preview():
    w, h = 1920, 1080
    img = Image.new("RGB", (w, h), color=(10, 14, 23))
    draw = ImageDraw.Draw(img)

    # Fonts
    try:
        font_title = ImageFont.truetype("arialbd.ttf", 24)
        font_h2 = ImageFont.truetype("arialbd.ttf", 18)
        font_body = ImageFont.truetype("arial.ttf", 14)
        font_mono = ImageFont.truetype("consola.ttf", 13)
        font_mono_bold = ImageFont.truetype("consolab.ttf", 15)
        font_stat_val = ImageFont.truetype("arialbd.ttf", 36)
    except Exception:
        font_title = font_h2 = font_body = font_mono = font_mono_bold = font_stat_val = ImageFont.load_default()

    # Subtle background cyber grid
    for x in range(0, w, 40):
        draw.line([(x, 0), (x, h)], fill=(15, 22, 35), width=1)
    for y in range(0, h, 40):
        draw.line([(0, y), (w, y)], fill=(15, 22, 35), width=1)

    # 1. Top Navbar / Header
    draw.rectangle([(0, 0), (w, 75)], fill=(17, 25, 39))
    draw.line([(0, 75), (w, 75)], fill=(0, 242, 254), width=2)

    # Logo / Title
    draw.ellipse([(35, 18), (75, 58)], fill=(0, 242, 254))
    draw.polygon([(55, 24), (70, 36), (65, 52), (55, 56), (45, 52), (40, 36)], fill=(10, 14, 23))
    draw.text((90, 18), "SENTINELAEGIS-X // DEFENSE COMMAND COCKPIT", fill=(255, 255, 255), font=font_title)
    draw.text((90, 46), "Autonomous Triage & Human-Authorized Remediation Engine", fill=(148, 163, 184), font=font_body)

    # Status Pill on Navbar
    draw.rounded_rectangle([(1480, 20), (1750, 54)], radius=17, outline=(255, 170, 0), width=1, fill=(35, 25, 10))
    draw.text((1500, 28), "⚠️ ZERO UNAPPROVED ACTIONS MODE", fill=(255, 170, 0), font=font_mono_bold)
    draw.ellipse([(1780, 33), (1792, 45)], fill=(0, 255, 153))
    draw.text((1805, 28), "ONLINE", fill=(0, 255, 153), font=font_mono_bold)

    # 2. Metric HUD Cards (Top row)
    metrics = [
        ("PENDING OPERATOR AUTHORIZATIONS", "1", (255, 51, 102), "Incidents Awaiting Kill/Quarantine"),
        ("QUARANTINED VAULT FILES", "4", (255, 170, 0), "XOR-Encrypted Payloads Isolated"),
        ("LEARNED THREAT SIGNATURES", "148", (0, 242, 254), "URLhaus & MalwareBazaar IOCs"),
        ("RESOLVED & DEFENDED THREATS", "26", (157, 78, 221), "Processed Incidents Logged")
    ]
    card_w = 425
    card_h = 110
    start_x = 40
    start_y = 105

    for i, (m_title, m_val, m_col, m_sub) in enumerate(metrics):
        cx = start_x + i * (card_w + 20)
        draw.rounded_rectangle([(cx, start_y), (cx + card_w, start_y + card_h)], radius=8, fill=(18, 26, 43), outline=(30, 45, 70), width=1)
        # Accent bar on left
        draw.rectangle([(cx, start_y), (cx + 5, start_y + card_h)], fill=m_col)
        draw.text((cx + 20, start_y + 14), m_title, fill=(148, 163, 184), font=font_mono)
        draw.text((cx + 20, start_y + 36), m_val, fill=(255, 255, 255), font=font_stat_val)
        draw.text((cx + 20, start_y + 82), m_sub, fill=(100, 116, 139), font=font_body)

    # 3. Left Panel: Threat Approval Queue (Main workspace)
    left_x = 40
    left_y = 240
    left_w = 1180
    left_h = 780
    draw.rounded_rectangle([(left_x, left_y), (left_x + left_w, left_y + left_h)], radius=10, fill=(14, 20, 32), outline=(30, 45, 70), width=1)
    
    # Left Panel Header
    draw.text((left_x + 25, left_y + 20), "🛡️ Threat Approval Queue (Standby Mode: Awaiting Operator Command)", fill=(255, 255, 255), font=font_h2)
    draw.text((left_x + 25, left_y + 45), "Engine has identified active threats across your filesystem and network. Zero moves made until authorized.", fill=(148, 163, 184), font=font_body)
    draw.line([(left_x + 20, left_y + 70), (left_x + left_w - 20, left_y + 70)], fill=(30, 45, 70), width=1)

    # Incident Card 1 (Critical Malware)
    ic1_y = left_y + 85
    ic1_h = 290
    draw.rounded_rectangle([(left_x + 20, ic1_y), (left_x + left_w - 20, ic1_y + ic1_h)], radius=8, fill=(18, 26, 43), outline=(255, 51, 102), width=1)
    # Header of Incident Card
    draw.text((left_x + 35, ic1_y + 16), "INCIDENT: INC-7B891A42", fill=(255, 255, 255), font=font_mono_bold)
    # Badge
    draw.rounded_rectangle([(left_x + 850, ic1_y + 12), (left_x + left_w - 35, ic1_y + 38)], radius=4, fill=(50, 15, 25), outline=(255, 51, 102), width=1)
    draw.text((left_x + 865, ic1_y + 16), "CRITICAL_MALWARE • SCORE: 95/100", fill=(255, 51, 102), font=font_mono_bold)

    # Path & Meta
    draw.text((left_x + 35, ic1_y + 48), "📁 Target File:", fill=(148, 163, 184), font=font_mono)
    draw.text((left_x + 160, ic1_y + 48), "C:\\Users\\wwwam\\Downloads\\suspicious_updater_patch.exe", fill=(0, 242, 254), font=font_mono)
    draw.text((left_x + 35, ic1_y + 70), "⚡ Process PID:", fill=(148, 163, 184), font=font_mono)
    draw.text((left_x + 160, ic1_y + 70), "4812 (Active handle open)", fill=(255, 255, 255), font=font_mono)
    draw.text((left_x + 35, ic1_y + 92), "🌐 Network IP:", fill=(148, 163, 184), font=font_mono)
    draw.text((left_x + 160, ic1_y + 92), "185.220.101.5 (Port 4444 - Metasploit C2 Beacon)", fill=(255, 170, 0), font=font_mono)
    draw.text((left_x + 35, ic1_y + 114), "🔑 SHA-256:", fill=(148, 163, 184), font=font_mono)
    draw.text((left_x + 160, ic1_y + 114), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", fill=(100, 116, 139), font=font_mono)

    # Reasons
    draw.text((left_x + 35, ic1_y + 140), "Detection Heuristics & Anomalies:", fill=(255, 255, 255), font=font_mono_bold)
    reasons = [
        "• Shannon Entropy: 7.84 (Highly packed / encrypted polymorphic payload)",
        "• Win32 API Imports: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread (Process Injection)",
        "• Discord Alert: Embed dispatched to #security-alerts (Awaiting your authorization)"
    ]
    for r_idx, r_text in enumerate(reasons):
        draw.text((left_x + 50, ic1_y + 165 + r_idx * 22), r_text, fill=(226, 232, 240), font=font_mono)

    # Action Buttons
    btn_y = ic1_y + 235
    # Button 1: Kill Process
    draw.rounded_rectangle([(left_x + 35, btn_y), (left_x + 220, btn_y + 40)], radius=6, fill=(255, 51, 102))
    draw.text((left_x + 55, btn_y + 12), "⚡ KILL PROCESS TREE", fill=(255, 255, 255), font=font_mono_bold)

    # Button 2: Quarantine
    draw.rounded_rectangle([(left_x + 235, btn_y), (left_x + 440, btn_y + 40)], radius=6, fill=(255, 170, 0))
    draw.text((left_x + 250, btn_y + 12), "🔒 QUARANTINE ENCRYPT", fill=(0, 0, 0), font=font_mono_bold)

    # Button 3: Linux Fightback / Firewall Drop
    draw.rounded_rectangle([(left_x + 455, btn_y), (left_x + 680, btn_y + 40)], radius=6, fill=(157, 78, 221))
    draw.text((left_x + 475, btn_y + 12), "⚔️ EXECUTE FIGHTBACK ALL", fill=(255, 255, 255), font=font_mono_bold)

    # Button 4: Dismiss
    draw.rounded_rectangle([(left_x + 695, btn_y), (left_x + 820, btn_y + 40)], radius=6, fill=(35, 45, 65))
    draw.text((left_x + 725, btn_y + 12), "✖ DISMISS", fill=(148, 163, 184), font=font_mono_bold)

    # Incident Card 2 (Phishing Email)
    ic2_y = ic1_y + ic1_h + 20
    ic2_h = 230
    draw.rounded_rectangle([(left_x + 20, ic2_y), (left_x + left_w - 20, ic2_y + ic2_h)], radius=8, fill=(18, 26, 43), outline=(255, 170, 0), width=1)
    draw.text((left_x + 35, ic2_y + 16), "INCIDENT: INC-3C1990F2", fill=(255, 255, 255), font=font_mono_bold)
    draw.rounded_rectangle([(left_x + 850, ic2_y + 12), (left_x + left_w - 35, ic2_y + 38)], radius=4, fill=(45, 30, 10), outline=(255, 170, 0), width=1)
    draw.text((left_x + 895, ic2_y + 16), "PHISHING_EMAIL • SCORE: 75/100", fill=(255, 170, 0), font=font_mono_bold)

    draw.text((left_x + 35, ic2_y + 48), "📧 Subject:", fill=(148, 163, 184), font=font_mono)
    draw.text((left_x + 160, ic2_y + 48), "URGENT: Your Gmail Account Security Verification Expiring", fill=(255, 255, 255), font=font_mono)
    draw.text((left_x + 35, ic2_y + 70), "👤 Sender Spoof:", fill=(148, 163, 184), font=font_mono)
    draw.text((left_x + 160, ic2_y + 70), "google-verify@sec-account-update.xyz (SPF/DKIM: FAIL)", fill=(255, 51, 102), font=font_mono)
    draw.text((left_x + 35, ic2_y + 92), "📎 Attachment:", fill=(148, 163, 184), font=font_mono)
    draw.text((left_x + 160, ic2_y + 92), "Invoice_Security_Check.docm (Macro Obfuscation Detected)", fill=(0, 242, 254), font=font_mono)

    btn2_y = ic2_y + 160
    draw.rounded_rectangle([(left_x + 35, btn2_y), (left_x + 250, btn2_y + 40)], radius=6, fill=(255, 170, 0))
    draw.text((left_x + 50, btn2_y + 12), "🔒 QUARANTINE ATTACHMENT", fill=(0, 0, 0), font=font_mono_bold)
    draw.rounded_rectangle([(left_x + 265, btn2_y), (left_x + 480, btn2_y + 40)], radius=6, fill=(157, 78, 221))
    draw.text((left_x + 285, btn2_y + 12), "🛡️ BLOCK SENDER DOMAIN", fill=(255, 255, 255), font=font_mono_bold)
    draw.rounded_rectangle([(left_x + 495, btn2_y), (left_x + 620, btn2_y + 40)], radius=6, fill=(35, 45, 65))
    draw.text((left_x + 525, btn2_y + 12), "✖ DISMISS", fill=(148, 163, 184), font=font_mono_bold)

    # 4. Right Panel: On-Demand Static Scanner & Threat Feeds
    right_x = 1245
    right_y = 240
    right_w = 635
    right_h = 780
    draw.rounded_rectangle([(right_x, right_y), (right_x + right_w, right_y + right_h)], radius=10, fill=(14, 20, 32), outline=(30, 45, 70), width=1)
    
    draw.text((right_x + 25, right_y + 20), "🔬 On-Demand Malware & PE Triage", fill=(255, 255, 255), font=font_h2)
    draw.text((right_x + 25, right_y + 45), "Drop any file to dissect headers, imports & entropy without execution.", fill=(148, 163, 184), font=font_body)
    draw.line([(right_x + 20, right_y + 70), (right_x + right_w - 20, right_y + 70)], fill=(30, 45, 70), width=1)

    # Drag & Drop Zone Box
    dz_y = right_y + 90
    dz_h = 160
    draw.rounded_rectangle([(right_x + 20, dz_y), (right_x + right_w - 20, dz_y + dz_h)], radius=8, fill=(10, 18, 30), outline=(0, 242, 254), width=2)
    draw.text((right_x + 230, dz_y + 35), "📁", font=font_stat_val)
    draw.text((right_x + 130, dz_y + 85), "Drop suspicious .exe, .elf, .ps1, or .eml here", fill=(255, 255, 255), font=font_mono_bold)
    draw.text((right_x + 185, dz_y + 115), "Or click to browse from disk", fill=(100, 116, 139), font=font_body)

    # Threat Intel Feed Synchronizer Box
    sync_y = dz_y + dz_h + 30
    draw.text((right_x + 25, sync_y), "🌐 Global Threat Intelligence Feeds", fill=(255, 255, 255), font=font_h2)
    draw.text((right_x + 25, sync_y + 25), "Synchronized with URLhaus & MalwareBazaar database feeds.", fill=(148, 163, 184), font=font_body)

    # Feed Status Items
    feed_items = [
        ("URLhaus Recent Malicious URLs", "Connected", "1,240 URLs Cached"),
        ("MalwareBazaar In-The-Wild Hashes", "Connected", "4,890 SHA256 Indexed"),
        ("Local Adaptive Neural Classifier", "Standby", "Weights Active (0.00ms)"),
        ("Linux Fightback Netfilter Bridge", "Active", "iptables Ready"),
        ("Discord Webhook Telemetry Pipe", "Verified", "HTTP 204 Active")
    ]
    for idx, (f_name, f_status, f_detail) in enumerate(feed_items):
        item_y = sync_y + 60 + idx * 55
        draw.rounded_rectangle([(right_x + 20, item_y), (right_x + right_w - 20, item_y + 45)], radius=6, fill=(18, 26, 43))
        draw.text((right_x + 35, item_y + 14), f_name, fill=(255, 255, 255), font=font_mono_bold)
        draw.text((right_x + 410, item_y + 14), f"[{f_status}]", fill=(0, 255, 153), font=font_mono)
        draw.text((right_x + 500, item_y + 14), f_detail, fill=(148, 163, 184), font=font_mono)

    # Sync Button
    btn_sync_y = sync_y + 360
    draw.rounded_rectangle([(right_x + 20, btn_sync_y), (right_x + right_w - 20, btn_sync_y + 45)], radius=6, fill=(0, 242, 254))
    draw.text((right_x + 180, btn_sync_y + 14), "🔄 SYNC THREAT FEEDS FROM INTERNET", fill=(10, 14, 23), font=font_mono_bold)

    # Save JPG
    out_file = "ui_design_preview.jpg"
    img.save(out_file, "JPEG", quality=95)
    print(f"Generated UI design visual: {os.path.abspath(out_file)}")


if __name__ == "__main__":
    render_ui_preview()
