

window.addEventListener('beforeunload', function () {
    localStorage.setItem("scrollPosition", this.window.scrollY);
});

window.addEventListener('load', function () {
    const scrollPosition = localStorage.getItem("scrollPosition");
    if (scrollPosition) {
        window.scrollTo(0, scrollPosition);
    };
})
