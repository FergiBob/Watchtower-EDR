
document.addEventListener("DOMContentLoaded", () => {
    const userBtn = document.querySelector(".user-btn");
    const dropdown = document.querySelector(".dropdown-content");

    if (userBtn && dropdown) {
        userBtn.addEventListener("click", (e) => {
            
            e.stopPropagation();
            
            // 2. Toggle the class
            dropdown.classList.toggle("is-active");
        });

        // 3. Close dropdown if clicking anywhere else on the document
        document.addEventListener("click", () => {
            dropdown.classList.remove("is-active");
        });
    }
});

function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

async function openUserModal(username) {
    try {
        const response = await fetch(`/api/v1/users/${username}`);
        const data = await response.json();

        const modal = document.getElementById('userModal');
        
        // Populate fields
        document.getElementById('modal-user-id').value = data.id;
        document.getElementById('edit-username').value = data.username;
        document.getElementById('edit-email').value = data.email;
        document.getElementById('modal-user-updated-on').innerText = data.updated_at;
        
        modal.style.display = 'flex';
    } catch (err) {
        console.error("Failed to load user details:", err);
    }
}

async function handleUserUpdate(event, username) {
    event.preventDefault();
    
    const csrfToken = getCookie("csrf_token");

    const payload = {
        username: document.getElementById('edit-username').value,
        email: document.getElementById('edit-email').value,
        password: document.getElementById('edit-password').value 
    };

    try {
        const response = await fetch(`/api/v1/users/${username}`, {
            method: 'PATCH',
            headers: { 
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken // Critical for passing backend validation
            },
            body: JSON.stringify(payload)
        });

        if (response.ok) {
            // Check if the backend requested a redirect (e.g., username changed)
            const redirectUrl = response.headers.get("X-Redirect");
            
            if (redirectUrl) {
                window.location.href = redirectUrl;
            } else {
                // Otherwise, just refresh for email/password updates
                location.reload(); 
            }
        } else if (response.status === 403) {
            alert("Security validation failed (CSRF).");
        } else {
            const errorText = await response.text();
            alert("Update failed: " + errorText);
        }
    } catch (err) {
        console.error("Update error:", err);
    }
}

function closeUserModal() {
    document.getElementById('userModal').style.display = 'none';
    document.body.style.overflow = 'auto';
    window.location.reload()
}