// SentinelAegis-X - Interactive Dashboard Controller

async function fetchStats() {
  try {
    const res = await fetch('/api/stats');
    if (!res.ok) return;
    const data = await res.json();
    document.getElementById('stat-pending').innerText = data.pending_incidents || 0;
    document.getElementById('stat-resolved').innerText = data.resolved_incidents || 0;
    document.getElementById('stat-vault').innerText = data.quarantined_files || 0;
    document.getElementById('stat-intel').innerText = data.learned_iocs || 0;
    const devElem = document.getElementById('stat-devices');
    if (devElem) devElem.innerText = data.connected_devices || 0;
  } catch (err) {
    console.error('Stats fetch error:', err);
  }
}

async function fetchIncidents() {
  try {
    const res = await fetch('/api/incidents?status=PENDING_OPERATOR_APPROVAL');
    if (!res.ok) return;
    const incidents = await res.json();
    const container = document.getElementById('incidents-container');

    if (!incidents || incidents.length === 0) {
      container.innerHTML = `
        <div style="text-align: center; padding: 3rem; color: #64748b;">
          <div style="font-size: 2.5rem; margin-bottom: 0.5rem;">🛡️</div>
          <div style="font-weight: 600;">No Pending Threats</div>
          <div style="font-size: 0.85rem; margin-top: 4px;">System is active and observing. Zero autonomous moves made.</div>
        </div>
      `;
      return;
    }

    container.innerHTML = incidents.map(inc => {
      const score = inc.threat_score || 0;
      let badgeClass = 'threat-safe';
      if (score >= 80) badgeClass = 'threat-critical';
      else if (score >= 50) badgeClass = 'threat-high';

      const reasonsHtml = (inc.summary || []).map(r => `<li>${escapeHtml(r)}</li>`).join('');

      return `
        <div class="incident-card" id="card-${inc.incident_id}">
          <div class="incident-meta">
            <span style="font-weight: 700; color: #fff;">${inc.incident_id}</span>
            <span class="badge-threat ${badgeClass}">${inc.classification} • SCORE ${score}</span>
          </div>
          <div class="incident-path">
            ${inc.target_path ? `📁 ${escapeHtml(inc.target_path)}` : ''}
            ${inc.target_pid ? ` | PID: <strong>${inc.target_pid}</strong>` : ''}
            ${inc.target_ip ? ` | Remote IP: <strong>${escapeHtml(inc.target_ip)}</strong>` : ''}
            ${inc.target_mac ? ` | MAC: <strong>${escapeHtml(inc.target_mac)}</strong>` : ''}
          </div>
          <ul class="incident-reasons">
            ${reasonsHtml}
          </ul>
          <div class="action-row">
            ${inc.target_pid ? `<button class="btn btn-kill" onclick="triggerAction('${inc.incident_id}', 'KILL')">⚡ Kill Process</button>` : ''}
            ${inc.target_path ? `<button class="btn btn-quarantine" onclick="triggerAction('${inc.incident_id}', 'QUARANTINE')">🔒 Quarantine Encrypt</button>` : ''}
            ${inc.target_ip ? `<button class="btn btn-kill" onclick="triggerAction('${inc.incident_id}', 'ISOLATE_IP')">🚫 Firewall Block IP</button>` : ''}
            <button class="btn btn-dismiss" onclick="triggerAction('${inc.incident_id}', 'DISMISS')">✖ Dismiss</button>
          </div>
        </div>
      `;
    }).join('');
  } catch (err) {
    console.error('Incident fetch error:', err);
  }
}

async function fetchDevices() {
  const container = document.getElementById('devices-container');
  if (!container) return;
  try {
    const res = await fetch('/api/network/devices');
    if (!res.ok) return;
    const data = await res.json();
    const devices = data.devices || [];

    if (devices.length === 0) {
      container.innerHTML = `<div style="color: var(--text-muted); font-size: 0.85rem;">No active ARP entries discovered. Click 'Scan Wi-Fi Subnet'.</div>`;
      return;
    }

    container.innerHTML = devices.map(dev => {
      let badgeCol = '#00f2fe';
      let tagText = 'SELF WORKSTATION';
      if (dev.is_gateway) {
        badgeCol = '#00ff99';
        tagText = 'GATEWAY ROUTER';
      } else if (!dev.is_known) {
        badgeCol = '#ffaa00';
        tagText = 'UNKNOWN PHONE / DEVICE';
      }

      return `
        <div style="background: rgba(13, 20, 36, 0.8); border: 1px solid rgba(255, 255, 255, 0.1); border-left: 4px solid ${badgeCol}; padding: 0.75rem 1rem; border-radius: 6px; display: flex; justify-content: space-between; align-items: center;">
          <div>
            <div style="font-weight: 600; font-size: 0.9rem; color: #fff;">
              ${escapeHtml(dev.ip)} <span style="font-size: 0.75rem; color: var(--text-muted); font-family: monospace;">[${escapeHtml(dev.mac)}]</span>
            </div>
            <div style="font-size: 0.8rem; color: #94a3b8; margin-top: 2px;">
              Brand / Manufacturer: <strong style="color: #e2e8f0;">${escapeHtml(dev.vendor)}</strong> | Hostname: ${escapeHtml(dev.hostname)}
            </div>
          </div>
          <span style="font-size: 0.75rem; font-weight: 700; color: ${badgeCol}; background: rgba(0,0,0,0.4); padding: 4px 8px; border-radius: 4px; border: 1px solid ${badgeCol};">
            ${tagText}
          </span>
        </div>
      `;
    }).join('');
  } catch (err) {
    console.error('Devices fetch error:', err);
  }
}

async function scanNetworkSubnet() {
  const container = document.getElementById('devices-container');
  if (container) container.innerHTML = `<div style="color: var(--accent-cyan);">🔍 Sweeping Wi-Fi subnet (192.168.1.0/24) for active phones & MACs...</div>`;
  try {
    const res = await fetch('/api/network/scan', { method: 'POST' });
    const data = await res.json();
    alert(`Subnet sweep completed: Found ${data.total_found} active devices (${data.unknown_count} unknown phones/devices).`);
    fetchDevices();
    fetchStats();
    fetchIncidents();
  } catch (err) {
    alert('Subnet scan error: ' + err);
  }
}

async function auditEmails() {
  const resultDiv = document.getElementById('email-audit-result');
  resultDiv.innerHTML = `<div style="color: var(--accent-cyan);">⚡ Auditing 30-60 day security alert history & device linkages...</div>`;
  try {
    const res = await fetch('/api/email/audit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ account: 'aman20770101@gmail.com', days_back: 60 })
    });
    const data = await res.json();
    resultDiv.innerHTML = `
      <div style="border-left: 3px solid #00f2fe; padding-left: 8px;">
        <div style="font-weight: 700; color: #fff;">Audit Initialized for 3 Target Accounts</div>
        <div style="font-size: 0.75rem; margin: 4px 0;">Accounts: <code>aman20770101@gmail.com</code>, <code>cornela778@gmail.com</code>, <code>rammishra9991@gmail.com</code></div>
        <div style="font-size: 0.75rem; color: #94a3b8;">${data.message || 'Inspection completed.'}</div>
      </div>
    `;
  } catch (err) {
    resultDiv.innerHTML = `<div style="color: #ff3366;">Email audit error: ${err}</div>`;
  }
}

async function triggerAction(incidentId, action) {
  if (!confirm(`Are you sure you want to authorize: ${action} on ${incidentId}?`)) return;

  try {
    const res = await fetch(`/api/incidents/${incidentId}/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: action, operator: 'Local Operator' })
    });
    const result = await res.json();
    if (result.success) {
      alert(`Action ${action} successfully executed!`);
      fetchStats();
      fetchIncidents();
    } else {
      alert(`Error executing action: ${result.error || 'Unknown'}`);
    }
  } catch (err) {
    alert(`Failed to send approval: ${err}`);
  }
}

function escapeHtml(text) {
  if (!text) return '';
  return text.replace(/[&<>"']/g, function(m) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[m];
  });
}

// Drag & drop file scanning
const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');

if (dropZone && fileInput) {
  dropZone.addEventListener('click', () => fileInput.click());
  dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('dragover'); });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) {
      uploadAndScan(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files.length > 0) {
      uploadAndScan(fileInput.files[0]);
    }
  });
}

async function uploadAndScan(file) {
  const resultDiv = document.getElementById('scan-result');
  resultDiv.innerHTML = `<div style="color: var(--accent-cyan);">🔬 Analyzing file structure, entropy, and headers...</div>`;
  
  const formData = new FormData();
  formData.append('file', file);

  try {
    const res = await fetch('/api/scan/file', {
      method: 'POST',
      body: formData
    });
    const analysis = await res.json();
    
    let color = '#00ff99';
    if (analysis.threat_score >= 80) color = '#ff3366';
    else if (analysis.threat_score >= 50) color = '#ffaa00';

    resultDiv.innerHTML = `
      <div style="border-left: 3px solid ${color}; padding-left: 8px;">
        <div style="font-weight: 700; color: ${color};">${analysis.classification} (Score: ${analysis.threat_score}/100)</div>
        <div style="font-size: 0.8rem; margin: 4px 0;">Entropy: <strong>${analysis.entropy}</strong> | Size: ${(analysis.file_size / 1024).toFixed(1)} KB</div>
        <div style="font-size: 0.75rem; color: #94a3b8; font-family: monospace;">SHA256: ${analysis.hashes ? analysis.hashes.sha256 : 'N/A'}</div>
        <ul style="margin-top: 6px; padding-left: 1rem; font-size: 0.8rem;">
          ${(analysis.reasons || []).map(r => `<li>${escapeHtml(r)}</li>`).join('')}
        </ul>
      </div>
    `;
    fetchStats();
    fetchIncidents();
  } catch (err) {
    resultDiv.innerHTML = `<div style="color: #ff3366;">Scan failed: ${err}</div>`;
  }
}

// Polling interval
fetchStats();
fetchIncidents();
fetchDevices();
setInterval(() => {
  fetchStats();
  fetchIncidents();
  fetchDevices();
}, 4000);
