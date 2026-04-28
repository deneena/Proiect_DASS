window.pwVisibility = function(id) {
    const x = document.getElementById(id);
    if (!x) return;
    x.type = x.type === "password" ? "text" : "password";
};