/*
  scroll-reveal.js
  ----------------
  Fades/slides elements with class "reveal" into view as they enter the
  viewport, using IntersectionObserver (no scroll-event polling needed).
  Purely cosmetic - degrades gracefully to "just visible" if JS fails.
*/
(function () {
    const items = document.querySelectorAll('.reveal');
    if (!items.length || !('IntersectionObserver' in window)) {
        items.forEach(el => el.classList.add('visible'));
        return;
    }

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.15 });

    items.forEach(el => observer.observe(el));
})();
