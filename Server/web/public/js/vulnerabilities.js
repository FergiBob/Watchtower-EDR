function formatDateTime(dateString) {
    if (!dateString || dateString === 'N/A') return 'N/A';
    
    // Replace space with 'T' if it's a SQL format string to make it ISO compliant for JS
    const date = new Date(dateString.replace(' ', 'T'));
    
    // Check if the date is actually valid
    if (isNaN(date.getTime())) return dateString;

    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function timeAgo(dateString) {
    if (!dateString || dateString === 'N/A') return '';
    const date = new Date(dateString.replace(' ', 'T'));
    const seconds = Math.floor((new Date() - date) / 1000);

    let interval = seconds / 31536000;
    if (interval > 1) return Math.floor(interval) + " years ago";
    interval = seconds / 2592000;
    if (interval > 1) return Math.floor(interval) + " months ago";
    interval = seconds / 86400;
    if (interval > 1) return Math.floor(interval) + " days ago";
    interval = seconds / 3600;
    if (interval > 1) return Math.floor(interval) + " hours ago";
    return "Just now";
}

/**
 * Triggers a full fleet re-scan for vulnerabilities.
 * Updated to match a standard POST /api/v1 pattern if desired.
 */
async function triggerVulnScan() {
    const btn = document.querySelector('.btn-primary');
    const originalContent = btn.innerHTML;

    // UI Feedback: Disable button and show loading state
    btn.disabled = true;
    btn.innerHTML = '<i class="bi bi-arrow-repeat spin"></i> Scanning Fleet...';

    try {
        const response = await fetch('/api/v1/vulnerabilities/scan', { 
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        const result = await response.json();

        if (response.ok) {
            // Success state
            btn.classList.replace('btn-primary', 'btn-success');
            btn.innerHTML = '<i class="bi bi-check-circle"></i> Scan Started';
            
            // Re-enable after 5 seconds
            setTimeout(() => {
                btn.disabled = false;
                btn.classList.replace('btn-success', 'btn-primary');
                btn.innerHTML = originalContent;
            }, 5000);
        } else {
            // Error state (e.g., 409 Conflict if already running)
            alert(result.message);
            btn.disabled = false;
            btn.innerHTML = originalContent;
        }
    } catch (err) {
        console.error("Scan trigger failed:", err);
        btn.disabled = false;
        btn.innerHTML = originalContent;
    }
}

/**
 * RESTful GET: Fetches details and populates the modal.
 */
async function openVulnerabilityModal(cveId, cpeUri) {
    const modal = document.getElementById('vulnerabilityModal');
    modal.style.display = 'flex';

    try {
        const response = await fetch(`/api/v1/vulnerabilities/${cveId}?cpe_uri=${encodeURIComponent(cpeUri)}`);
        const data = await response.json();

        statusSelect = document.getElementById('status-select')
        statusSelect.dataset.cveId = cveId;
        statusSelect.dataset.currentCpe = cpeUri;

        // 1. Header & Status
        document.getElementById('modal-cve-id').innerText = data.cve_id;
        document.getElementById('status-select').value = data.status;
        
        const sevBadge = document.getElementById('modal-severity');
        sevBadge.innerText = data.severity;
        updateSeverityStyle(sevBadge, data.severity);

        // 2. Intelligence
        document.getElementById('modal-description').innerText = data.description;
        document.getElementById('modal-exploit-score').innerText = data.exploit_score || '0.0';
        document.getElementById('modal-impact-score').innerText = data.impact_score || '0.0';

        // 3. Discovery Context
        document.getElementById('modal-score').innerText = data.cvss_score;
        document.getElementById('modal-target-type').innerText = data.target_type;
        document.getElementById('modal-agent-count').innerText = `${data.agent_count} Agents`;
        document.getElementById('modal-cpe').innerText = cpeUri;
        document.getElementById('modal-software-id').title = data.software_id

        const cpeDisplay = document.getElementById('modal-cpe');
        const cpeLink = document.getElementById('modal-cpe-link');
        
        cpeDisplay.innerText = cpeUri;
        cpeLink.href = `/software?search=${encodeURIComponent(cpeUri)}`;

        // 4. Timestamps
        // Timestamps
        document.getElementById('modal-published').innerText = formatDateTime(data.publish_date);
        document.getElementById('modal-modified').innerText = formatDateTime(data.last_modified);
        const detectionText = `${formatDateTime(data.detected_at)} (${timeAgo(data.detected_at)})`;
        document.getElementById('modal-first-detected').innerText = detectionText;

    } catch (err) {
        console.error("Failed to load details:", err);
    }
}

function viewAffectedAgents() {
    softwareID = document.getElementById('modal-software-id').title
    // Redirect to the agents page with a filter applied
    window.location.href = `/agents?software_id=${softwareID}`;
}

/**
 * RESTful PATCH: Updates the remediation status.
 */
async function patchVulnerabilityStatus() {
    const statusSelect = document.getElementById('status-select');
    const newStatus = statusSelect.value;
    const cveId = statusSelect.dataset.cveId;
    const cpeUri = statusSelect.dataset.currentCpe;

    // Visual feedback: Disable select while saving
    statusSelect.disabled = true;

    try {
        const response = await fetch(`/api/v1/vulnerabilities/${cveId}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                status: newStatus,
                cpe_uri: cpeUri
            })
        });

        if (response.ok) {
            console.log("Resource patched successfully.");
            // OPTIONAL: Update the specific table row text/color silently
            updateTableRowStatus(cveId, cpeUri, newStatus);
        } else {
            throw new Error("Update failed");
        }
    } catch (error) {
        alert("Failed to save status change.");
    } finally {
        statusSelect.disabled = false;
    }
}

/**
 * Helper: Updates the table UI without a page reload.
 * This looks for the row where CPE and CVE match.
 */
function updateTableRowStatus(cveId, cpeUri, status) {
    const rows = document.querySelectorAll('tr[data-cpe]');
    rows.forEach(row => {
        // You'll need to ensure your <tr> has data-cve and data-cpe attributes
        if (row.dataset.cpe === cpeUri && row.innerText.includes(cveId)) {
            const statusCell = row.querySelector('.status-text'); // Adjust selector as needed
            if (statusCell) {
                statusCell.innerText = status;
                statusCell.style.textTransform = "capitalize";
            }
        }
    });
}

/**
 * UI Helpers
 */
function closeModal() {
    document.getElementById('vulnerabilityModal').style.display = 'none';
    document.body.style.overflow = 'auto';
    window.location.reload()
}

function updateSeverityStyle(el, severity) {
    const colors = { 'critical': '#ff5555', 'high': '#ffb86c', 'medium': '#f1fa8c', 'low': '#50fa7b' };
    el.style.backgroundColor = colors[severity.toLowerCase()] || '#44475a';
    el.style.color = (severity.toLowerCase() === 'medium') ? '#282a36' : '#fff';
}

// Close on Click-Outside
window.addEventListener('click', (e) => {
    const modal = document.getElementById('vulnerabilityModal');
    if (e.target === modal) closeModal();
});

// Close on Escape
document.addEventListener('keydown', (e) => {
    if (e.key === "Escape") closeModal();
});