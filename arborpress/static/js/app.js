/* app.js – minimale Client-seitige Logik (§10: kein CDN) */

// §10 CSRF-Token: aus dem Meta-Tag auslesen und in alle Admin-Formulare injizieren.
// Vom Proxy weitergeleiteter Cookie ist HttpOnly, daher nur über diesen Mechanismus.
(function injectCsrfTokens() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  if (!meta) return; // kein Admin-Kontext, nichts zu tun
  const token = meta.getAttribute("content");
  if (!token) return;
  document.querySelectorAll("form").forEach((form) => {
    // Nur falls noch kein _csrf-Feld existiert
    if (!form.querySelector('input[name="_csrf"]')) {
      const input = document.createElement("input");
      input.type = "hidden";
      input.name = "_csrf";
      input.value = token;
      form.prepend(input);
    }
  });

  // Auch alle zukünftig per JS hinzugefügten Formulare absichern (MutationObserver)
  new MutationObserver((mutations) => {
    for (const m of mutations) {
      for (const node of m.addedNodes) {
        if (node.nodeType !== 1) continue;
        const forms = node.matches?.("form") ? [node] : [...node.querySelectorAll("form")];
        forms.forEach((form) => {
          if (!form.querySelector('input[name="_csrf"]')) {
            const input = document.createElement("input");
            input.type = "hidden";
            input.name = "_csrf";
            input.value = token;
            form.prepend(input);
          }
        });
      }
    }
  }).observe(document.body, { childList: true, subtree: true });
})();

// Flash-Messages nach 5s ausblenden
document.querySelectorAll(".flash").forEach((el) => {
  setTimeout(() => {
    el.style.transition = "opacity .4s";
    el.style.opacity = "0";
    setTimeout(() => el.remove(), 400);
  }, 5000);
});
