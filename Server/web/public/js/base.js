console.log("JS loaded successfully")

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
