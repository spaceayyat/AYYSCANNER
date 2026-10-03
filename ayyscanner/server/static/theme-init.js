// Runs before first paint (loaded synchronously in <head>) so the saved theme
// applies with no flash. "System" is represented by having no data-theme attribute.
(function () {
  try {
    var saved = localStorage.getItem("ayyscanner.theme");
    if (saved === "light" || saved === "dark") document.documentElement.dataset.theme = saved;
  } catch (e) { /* storage unavailable: fall back to the system theme */ }
})();
