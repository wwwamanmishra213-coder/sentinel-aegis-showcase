"""
SentinelAegis-X - PDF Foundation & Architecture Generator
Generates comprehensive offline engineering blueprint: SENTINEL_CYBER_FOUNDATION.pdf
Covers system architecture, mathematical threat scoring, Linux fightback mechanism,
Discord C2 integration, Human-in-the-Loop gating, and Git version control setup.
"""

import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether


def generate_pdf(filename="SENTINEL_CYBER_FOUNDATION.pdf"):
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        rightMargin=40, leftMargin=40,
        topMargin=40, bottomMargin=40
    )

    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=24,
        textColor=colors.HexColor('#0a192f'),
        spaceAfter=12
    )

    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=15,
        textColor=colors.HexColor('#00557f'),
        spaceBefore=14,
        spaceAfter=8,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        textColor=colors.HexColor('#222222'),
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13.5,
        textColor=colors.HexColor('#1f2937'),
        spaceAfter=6
    )

    code_style = ParagraphStyle(
        'Code_Custom',
        parent=styles['Code'],
        fontName='Courier',
        fontSize=8,
        leading=10.5,
        textColor=colors.HexColor('#0d1117'),
        backColor=colors.HexColor('#f6f8fa'),
        borderColor=colors.HexColor('#d0d7de'),
        borderWidth=1,
        borderPadding=6,
        spaceBefore=6,
        spaceAfter=8
    )

    story = []

    # Title & Metadata
    story.append(Paragraph("SENTINELAECIS-X CYBER DEFENSE PLATFORM", title_style))
    story.append(Paragraph("<b>Engineering Blueprint: Autonomous Analysis, Human-Authorized Remediation & Linux Fightback</b>", styles['Normal']))
    story.append(Spacer(1, 10))

    meta_table_data = [
        ["Classification:", "Confidential // Security Engineering Workspace", "Target OS:", "Windows 11 / Kali Linux"],
        ["Platform Architecture:", "Autonomous Multi-Vector Telemetry & Human Gate", "Defense Mode:", "Zero-Autonomous Destruction (Enforced)"],
        ["C2 & Alerts:", "Discord Webhooks & Embedded Bot Commands", "Web Console:", "Glassmorphism Cyber Cockpit (FastAPI)"]
    ]
    t = Table(meta_table_data, colWidths=[130, 200, 80, 120])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f1f5f9')),
        ('TEXTCOLOR', (0,0), (-1,-1), colors.HexColor('#0f172a')),
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1'))
    ]))
    story.append(t)
    story.append(Spacer(1, 14))

    # Executive Summary
    story.append(Paragraph("1. Executive Threat Architecture & Philosophy", h1_style))
    story.append(Paragraph(
        "Modern defensive engineering requires rapid, internet-wide threat discovery without risking unintended downtime or collateral file destruction. "
        "<b>SentinelAegis-X</b> is engineered with a strict <b>Human-In-The-Loop Approval Gate (Zero-Move Guarantee)</b>: the system continuously watches "
        "filesystems, network sockets, Wi-Fi interfaces, and inbound emails, triaging threats and computing Shannon entropy and PE/ELF heuristics. "
        "However, the engine <i>will never terminate a process, alter network routes, or wipe files</i> until the human operator issues an explicit "
        "<b>KILL</b>, <b>QUARANTINE</b>, or <b>ISOLATE</b> command via the Web UI or Discord bot.",
        body_style
    ))

    # Architecture Table
    story.append(Spacer(1, 6))
    arch_data = [
        ["Subsystem", "Operational Role", "Engine Module", "Enforcement Hook"],
        ["Triage & Analyzer", "Shannon entropy, PE imports, ELF strings, YARA", "core.analyzer", "Static Analysis (Zero Execution)"],
        ["Threat Harvester", "Pulls live hashes from URLhaus & MalwareBazaar", "core.learning_engine", "Adaptive Pattern Assimilation"],
        ["Human Gatekeeper", "Incidents registered; locks remediation actions", "core.human_gate", "Mandatory Operator Approval"],
        ["Remediation Engine", "Process tree kill, XOR file quarantine, firewall drop", "core.remediation", "Linux iptables / Windows netsh"],
        ["Discord C2 Bot", "Rich telemetry embeds, mobile operator approvals", "core.discord_c2", "Webhook & Interactive Commands"],
        ["Operator Cockpit", "Glassmorphism UI, 1-click approvals, manual scan", "ui / FastAPI backend", "Real-Time WebSocket & REST"]
    ]
    t2 = Table(arch_data, colWidths=[100, 170, 110, 150])
    t2.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#00557f')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#94a3b8')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')])
    ]))
    story.append(t2)

    # Core Features Detail
    story.append(Spacer(1, 12))
    story.append(Paragraph("2. Mathematical Threat Scoring & Static Heuristics", h1_style))
    story.append(Paragraph(
        "Files entering monitored endpoints (Downloads, Temp, Startup) undergo binary inspection without spawning process execution:<br/>"
        "• <b>Shannon Entropy (H):</b> Evaluates bit randomness. A score exceeding 7.2 indicates packed, encrypted, or obfuscated payloads (typical of polymorphic ransomware and stealth droppers).<br/>"
        "• <b>PE Import Address Table (IAT) Inspection:</b> Win32 injection and evasive APIs (<code>VirtualAllocEx</code>, <code>WriteProcessMemory</code>, <code>CreateRemoteThread</code>, <code>GetAsyncKeyState</code>) add weighted hazard scores.<br/>"
        "• <b>Linux ELF Validation:</b> Identifies embedded shell execution primitives (<code>/bin/sh</code>, <code>/dev/tcp</code>) and stripped symbols.",
        body_style
    ))

    story.append(Paragraph("3. Cross-Platform Fightback Mechanism (Linux & Windows)", h1_style))
    story.append(Paragraph(
        "When the operator authorizes remediation, the engine executes targeted countermeasures tailored to the OS:<br/>"
        "• <b>Linux Fightback:</b> Applies stateful Netfilter rules:<br/>"
        "&nbsp;&nbsp;<code>iptables -A INPUT -s &lt;attacker_ip&gt; -j DROP</code><br/>"
        "&nbsp;&nbsp;<code>iptables -A OUTPUT -d &lt;attacker_ip&gt; -j DROP</code><br/>"
        "&nbsp;&nbsp;Recursively severs child processes using POSIX <code>SIGKILL</code>.<br/>"
        "• <b>Windows Defense:</b> Creates targeted <code>netsh advfirewall</code> rules and invokes recursive process tree termination via <code>taskkill /F /T /PID</code>.<br/>"
        "• <b>XOR Encrypted Vault:</b> Instead of risking accidental reinfection, quarantined binaries are byte-scrambled with key <code>0xA5</code>, stripped of execution flags, and stored in <code>./vault/*.vault</code> alongside cryptographic metadata.",
        body_style
    ))

    # Page Break for Setup & Git Instructions
    story.append(PageBreak())

    story.append(Paragraph("4. Discord Telemetry & C2 Integration", h1_style))
    story.append(Paragraph(
        "To link your newly created Discord server:<br/>"
        "1. In Discord: Go to <b>Server Settings -&gt; Integrations -&gt; Webhooks -&gt; New Webhook</b>.<br/>"
        "2. Copy the Webhook URL and paste it into <code>config/settings.json</code> under <code>discord.webhook_url</code>.<br/>"
        "3. When a threat is detected, an embed alert is dispatched displaying Incident ID, Threat Score, SHA-256, and target paths.<br/>"
        "4. Remediation can be approved directly via the web dashboard or configured Discord bot commands.",
        body_style
    ))

    story.append(Paragraph("5. Local Git Repository Synchronization Guide", h1_style))
    story.append(Paragraph(
        "Every line of source code, configuration, rules, and UI files is managed via Git. Quarantined malware samples and offline documentation are kept safe locally.<br/>"
        "Execute the following commands to initialize and push to your remote repository:",
        body_style
    ))

    git_script_text = (
        "# 1. Initialize local Git repository (if not already initiated)\n"
        "git init\n\n"
        "# 2. Configure safe permissions and inspect staged files\n"
        "git add .\n"
        "git status\n\n"
        "# 3. Create baseline release commit\n"
        "git commit -m \"feat: SentinelAegis-X autonomous analysis & human-in-the-loop defense engine\"\n\n"
        "# 4. Link to your GitHub or GitLab remote server\n"
        "git remote add origin https://github.com/YOUR_USERNAME/sentinel-aegis-defense.git\n\n"
        "# 5. Push all code to main branch\n"
        "git branch -M main\n"
        "git push -u origin main"
    )
    story.append(Paragraph(git_script_text.replace("\n", "<br/>"), code_style))

    story.append(Paragraph("6. Operational Quickstart", h1_style))
    quickstart_text = (
        "# Install dependencies\n"
        "pip install -r requirements.txt\n\n"
        "# Run complete verification test suite\n"
        "python scripts/test_engine.py\n\n"
        "# Launch master defense daemon (Web Cockpit + Filesystem & Network Sentinels)\n"
        "python main.py\n\n"
        "# Open Operator Cockpit in your browser:\n"
        "# http://127.0.0.1:8800"
    )
    story.append(Paragraph(quickstart_text.replace("\n", "<br/>"), code_style))

    doc.build(story)
    print(f"Generated PDF documentation: {os.path.abspath(filename)}")


if __name__ == "__main__":
    generate_pdf()
