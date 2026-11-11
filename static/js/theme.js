// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Naby Sidime. LogSonar : https://github.com/NabySidime/LogSonar
// Applique le thème mémorisé avant l'affichage (évite le flash clair/sombre)
(function () {
  try {
    var t = localStorage.getItem("logsonar-theme");
    if (t === "dark" || t === "light") document.documentElement.setAttribute("data-theme", t);
  } catch (e) { /* stockage indisponible : thème du système */ }
})();
