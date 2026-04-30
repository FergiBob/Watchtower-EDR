let activeAgent = null;

// Helper to turn ISO strings into Human Readable format
function formatDate(dateString) {
    if (!dateString || dateString === "0001-01-01T00:00:00Z") return "Never";
    const options = { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' };
    return new Date(dateString).toLocaleDateString(undefined, options);
}

async function openAgentModal(id) {
    
    const resp = await fetch(`/api/agent/${id}`);
    if (!resp.ok) return alert("Failed to fetch agent details.");
    
    const data = await resp.json();

    document.getElementById('m-hostname').innerText = data.hostname;
    document.getElementById('m-os-name').innerText = data.os_name;
    document.getElementById('m-agent-id').innerText = data.agent_id;
    document.getElementById('editCategory').value = data.category || "";
    document.getElementById('editDescription').value = data.description || "";
    
    document.getElementById('m-ip').innerText = data.ip_address;
    document.getElementById('m-os-ver').innerText = data.os_version;
    document.getElementById('m-os-build').innerText = data.os_build;
    document.getElementById('m-os-cpe').innerText = data.os_cpe_uri || "N/A";
    document.getElementById('m-binary').innerText = data.binary_version;

    // Use the new date formatter
    document.getElementById('m-first-seen').innerText = formatDate(data.first_seen);
    document.getElementById('m-last-seen').innerText = formatDate(data.last_seen);

    document.getElementById('agentModal').style.display = 'flex';
}

function closeAgentModal() {
    document.getElementById('agentModal').style.display = 'none';
}

document.getElementById('saveAgentBtn').onclick = async () => {
    const payload = {
        category: document.getElementById('editCategory').value,
        description: document.getElementById('editDescription').value
    };

    const res = await fetch(`/api/agent/${id}/metadata`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
    });

    if (res.ok) location.reload();
};

document.getElementById('decomBtn').onclick = async () => {
    // Standardizing status logic: Active, Offline, Decommissioned
    if (confirm("Decommissioning will permanently mark this agent as inactive. Proceed?")) {
        const res = await fetch(`/api/agent/${activeAgent}/decommission`, { method: 'POST' });
        if (res.ok) location.reload();
    }
};

// Function to handle installer downloads based on selected OS
async function downloadInstaller(osType) {
    const btn = document.getElementById(`btn-dl-${osType}`);
    const originalText = btn.innerHTML;
    
    // UI Feedback
    btn.innerHTML = '<i class="bi bi-hourglass-split"></i> Generating...';
    btn.disabled = true;

    try {
        const response = await fetch(`/api/installer/generate?os=${osType}`);
        
        if (!response.ok) {
            throw new Error("Server failed to generate installer");
        }

        // Process the file download
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        
        // Set filename based on OS
        a.download = osType === 'windows' ? 'install-watchtower.ps1' : 'install-watchtower.sh';
        
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        a.remove();
    } catch (err) {
        console.error(err);
        alert("Error generating installer: " + err.message);
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

// Logic to open the "Add Agent" Selection Modal
function openAddAgentModal() {
    document.getElementById('addAgentModal').style.display = 'flex';
}

function closeAddAgentModal() {
    document.getElementById('addAgentModal').style.display = 'none';
}