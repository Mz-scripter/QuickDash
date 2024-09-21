// Prevent anchor tags default behaviour on the bottom navbar
document.querySelector('.nav-item').addEventListener('click', function(event) {
    event.preventDefault();
});
