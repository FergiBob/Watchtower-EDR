let currentSw = {};

/**
 * Toggles the visibility of the action menu for a specific table row.
 */
function toggleActionMenu(button, event) {
    event.stopPropagation();
    const menu = button.nextElementSibling;
    
    // Close all other action menus to prevent overlap
    document.querySelectorAll('.action-menu-content').forEach(m => {
        if (m !== menu) m.classList.remove('show');
    });

    // Toggle the 'show' class on the clicked menu
    if (menu) {
        menu.classList.toggle('show');
    }
}

/**
 * Opens the Custom CPE Mapping Modal and pre-fills search fields.
 */
function openCPEModal(id, name, vendor, version) {
    // Store current software details for the final mapping save
    currentSw = { id, name, vendor, version };

    const modalOverlay = document.getElementById('cpeModalOverlay');
    const modalSwName = document.getElementById('modalSwName');
    
    // Get the new individual search inputs
    const productInput = document.getElementById('cpeSearchProduct');
    const vendorInput = document.getElementById('cpeSearchVendor');
    const versionInput = document.getElementById('cpeSearchVersion');

    // Set the header title
    if (modalSwName) {
        modalSwName.innerHTML = `
            <strong style="margin-right: 5px;">Name:</strong> ${name} 
            <span style="margin-left: 20px;">
                <strong style="margin-right: 5px;">Version:</strong> ${version}
            </span>
            <span style="margin-left: 20px;">
                <strong style="margin-right: 5px;">Vendor:</strong> ${vendor}
            </span>
        `;
    }

    // Pre-fill the search boxes with the current software data
    if (productInput) productInput.value = name || "";
    if (vendorInput) vendorInput.value = vendor || "";
    if (versionInput) versionInput.value = version || "";

    // Show the modal
    if (modalOverlay) {
        modalOverlay.classList.add('active');
        
        // Automatically trigger the first search based on pre-filled data
        performCPESearch(); 
    } else {
        console.error("Could not find element with ID 'cpeModalOverlay'");
    }
}
/**
 * Closes the custom modal
 */
function closeCPEModal() {
    const modalOverlay = document.getElementById('cpeModalOverlay');
    if (modalOverlay) {
        modalOverlay.classList.remove('active');
    }
}

async function performCPESearch() {
    const product = document.getElementById('cpeSearchProduct').value.trim();
    const vendor = document.getElementById('cpeSearchVendor').value.trim();
    const version = document.getElementById('cpeSearchVersion').value.trim();
    
    const resultsBody = document.getElementById('cpeResultsBody');
    const loader = document.getElementById('searchLoader');

    // Basic validation: at least one field should have data
    if (!product && !vendor && !version) {
        resultsBody.innerHTML = '<tr><td colspan="2" class="text-center py-4">Please enter at least one search term.</td></tr>';
        return;
    }

    if (loader) loader.classList.remove('d-none');
    resultsBody.innerHTML = '';

    try {
        // Construct query params
        const params = new URLSearchParams({
            product: product,
            vendor: vendor,
            version: version
        });

        const response = await fetch(`/api/cpe/search?${params.toString()}`);
        const results = await response.json();
        
        if (!results || results.length === 0) {
            resultsBody.innerHTML = '<tr><td colspan="2" class="text-center py-4">No CPEs found matching those filters.</td></tr>';
            return;
        }

        results.forEach(item => {
            const row = `<tr>
                <td class="text-capitalize"><strong>${item.product}</strong></td>
                <td class="text-capitalize">${item.vendor}</td>
                <td><span class="badge bg-secondary">${item.version}</span></td>
                <td><code class="small" style="color: var(--accent-primary);">${item.cpe_uri}</code></td>
                <td class="text-end">
                    <button class="btn-hollow btn-small" 
                            onclick="saveMapping('${item.cpe_uri}')">
                        <i class="bi bi-check2"></i> Select
                    </button>
                </td>
            </tr>`;
            resultsBody.innerHTML += row;
        });
    } catch (err) {
        resultsBody.innerHTML = '<tr><td colspan="2" class="text-danger text-center py-4">Error querying dictionary.</td></tr>';
    } finally {
        if (loader) loader.classList.add('d-none');
    }
}
async function saveMapping(selectedCpe) {
    // 1. We use the PUT method to indicate we are updating the 'cpe' resource
    // 2. The URL targets the specific sub-resource of the software asset
    try {
        const response = await fetch(`/api/software/${currentSw.id}/cpe`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ cpe: selectedCpe })
        });

        if (response.ok) {
            closeCPEModal();
            alert(`Updated mapping for ${currentSw.name} ${currentSw.version}`);
            location.reload(); 
        } else {
            const errorMsg = await response.text();
            alert(`Failed to save mapping: ${errorMsg}`);
        }
    } catch (err) {
        console.error("Error saving mapping:", err);
    }
}

async function unbindCPE() {
    if (!currentSw || !currentSw.id) return;

    const confirmUnbind = confirm(`Are you sure you want to stop tracking security risks for ${currentSw.name}?`);
    
    if (confirmUnbind) {
        try {
            // 1. We use DELETE to remove the relationship entirely
            // 2. This is more semantic than sending an empty string via PUT
            const response = await fetch(`/api/software/${currentSw.id}/cpe`, {
                method: 'DELETE'
            });

            if (response.ok) {
                console.log("Software mapping deleted successfully");
                closeCPEModal();
                
                // Refresh logic
                if (typeof refreshSoftwareTable === "function") {
                    refreshSoftwareTable();
                } else {
                    location.reload();
                }
            } else {
                alert("Failed to unbind software.");
            }
        } catch (err) {
            alert("Network error while unbinding software.");
            console.error(err);
        }
    }
}

// Initialization block for Event Listeners
document.addEventListener('DOMContentLoaded', () => {
    // 1. Close menus/modals when clicking away
    document.addEventListener('click', (e) => {
        // Close Action Dropdowns
        if (!e.target.closest('.action-dropdown')) {
            document.querySelectorAll('.action-menu-content').forEach(m => {
                m.classList.remove('show');
            });
        }
        
        // Close Modal if clicking the backdrop
        const modalOverlay = document.getElementById('cpeModalOverlay');
        if (e.target === modalOverlay) {
            closeCPEModal();
        }
    });

    // 2. Allow "Enter" key to trigger search
    const cpeSearchInput = document.getElementById('cpeSearchInput');
    if (cpeSearchInput) {
        cpeSearchInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') performCPESearch();
        });
    }
});