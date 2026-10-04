// Runs before first paint (loaded synchronously in <head>) so the saved theme and interface size
// apply with no flash. "System" is represented by having no data-theme attribute. The server keeps
// the real, permanent copy of these settings; this is only a fast local cache of them.
(function () {
  try {
    var saved = localStorage.getItem("ayyscanner.theme");
    if (saved === "light" || saved === "dark") document.documentElement.dataset.theme = saved;
    var scale = parseInt(localStorage.getItem("ayyscanner.scale"), 10);
    if (scale >= 80 && scale <= 150) document.documentElement.style.setProperty("--ui-zoom", String(scale / 100));
  } catch (e) { /* storage unavailable: fall back to the defaults */ }
})();
