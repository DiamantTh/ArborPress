/* app.js – minimale Client-seitige Logik (§10: kein CDN) */

// Flash-Messages nach 5s ausblenden
document.querySelectorAll(".flash").forEach((el) => {
  setTimeout(() => {
    el.style.transition = "opacity .4s";
    el.style.opacity = "0";
    setTimeout(() => el.remove(), 400);
  }, 5000);
});
