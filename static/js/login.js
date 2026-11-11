// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Naby Sidime. LogSonar : https://github.com/NabySidime/LogSonar
(function () {
  "use strict";
  var challenge = null;
  var $ = function (id) { return document.getElementById(id); };

  function show(step) {
    ["loading", "setup", "login", "enroll", "totp"].forEach(function (s) {
      $("step-" + s).classList.toggle("hidden", s !== step);
    });
    var focus = { setup: "s-code", login: "l-user", enroll: "e-code", totp: "t-code" }[step];
    if (focus) setTimeout(function () { $(focus).focus(); }, 30);
  }

  async function post(url, body) {
    var res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-LogSonar": "1" },
      credentials: "same-origin",
      body: JSON.stringify(body),
    });
    var data = {};
    try { data = await res.json(); } catch (e) { /* réponse vide */ }
    if (!res.ok) {
      var msg = data.detail;
      if (Array.isArray(msg)) msg = "Champ invalide : " + msg.map(function (d) { return (d.loc || []).slice(-1)[0]; }).join(", ");
      throw new Error(msg || "Erreur " + res.status);
    }
    return data;
  }

  function handleStep(data) {
    challenge = data.challenge;
    if (data.step === "enroll") {
      // Le SVG du QR code est généré par le serveur (qrcode) : on l'insère via DOMParser
      var doc = new DOMParser().parseFromString(data.qr_svg, "image/svg+xml");
      var svg = doc.documentElement;
      $("qr").replaceChildren(document.importNode(svg, true));
      $("secret").textContent = data.secret.replace(/(.{4})/g, "$1 ").trim();
      show("enroll");
    } else if (data.step === "totp") {
      show("totp");
    }
  }

  function bind(formId, errId, fn) {
    $(formId).addEventListener("submit", async function (ev) {
      ev.preventDefault();
      var btn = ev.target.querySelector("button[type=submit]");
      $(errId).textContent = "";
      btn.disabled = true;
      try { await fn(); } catch (e) { $(errId).textContent = e.message; }
      btn.disabled = false;
    });
  }

  bind("form-setup", "err-setup", async function () {
    if ($("s-pass").value !== $("s-pass2").value) throw new Error("Les mots de passe ne correspondent pas.");
    handleStep(await post("/api/auth/setup", {
      setup_code: $("s-code").value.trim(), username: $("s-user").value.trim(),
      email: $("s-email").value.trim(), password: $("s-pass").value,
    }));
  });

  bind("form-login", "err-login", async function () {
    handleStep(await post("/api/auth/login", { username: $("l-user").value.trim(), password: $("l-pass").value }));
  });

  async function verify(inputId) {
    await post("/api/auth/2fa", { challenge: challenge, code: $(inputId).value.replace(/\s/g, "") });
    window.location.replace("/");
  }
  bind("form-enroll", "err-enroll", function () { return verify("e-code"); });
  bind("form-totp", "err-totp", function () {
    return verify("t-code").catch(function (e) {
      $("t-code").value = "";
      if (/reconnectez|expirée/i.test(e.message)) { show("login"); $("err-login").textContent = e.message; return; }
      throw e;
    });
  });
  $("back-login").addEventListener("click", function () { show("login"); });

  // Soumission automatique dès 6 chiffres
  ["e-code", "t-code"].forEach(function (id) {
    $(id).addEventListener("input", function () {
      if (this.value.replace(/\D/g, "").length === 6) this.form.requestSubmit();
    });
  });

  if (window.lucide) lucide.createIcons();
  fetch("/api/auth/status", { credentials: "same-origin" })
    .then(function (r) { return r.json(); })
    .then(function (s) {
      if (s.authenticated) window.location.replace("/");
      else show(s.needs_setup ? "setup" : "login");
    })
    .catch(function () { show("login"); });
})();
