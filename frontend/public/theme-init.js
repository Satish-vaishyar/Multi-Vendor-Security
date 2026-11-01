/* Runs synchronously before first paint (CSP-safe external script) so the saved theme is applied with no flash. */
(function () {
  try {
    var pref = localStorage.getItem("qirova_theme") || "system";
    var dark = pref === "dark" || (pref === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
    document.documentElement.dataset.theme = dark ? "dark" : "light";
    document.documentElement.style.colorScheme = dark ? "dark" : "light";
  } catch {
    /* storage blocked: stay on the light default */
  }
})();
