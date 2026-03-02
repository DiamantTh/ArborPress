/**
 * WebAuthn Registrierung – §2
 * Registriert einen neuen Sicherheitsschlüssel/Passkey.
 */

const regForm = document.getElementById("register-form");
const regBtn  = document.getElementById("register-btn");

if (regForm) {
  regForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const userName    = regForm.querySelector("#user_name").value.trim();
    const displayName = regForm.querySelector("#display_name").value.trim();
    const keyLabel    = regForm.querySelector("#key_label").value.trim() || "Sicherheitsschlüssel";

    regBtn.disabled = true;
    regBtn.textContent = "Bitte Schlüssel berühren…";

    try {
      const beginRes = await fetch("/auth/register/begin", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user_name: userName, display_name: displayName }),
      });
      if (!beginRes.ok) throw new Error(await beginRes.text());
      const options = await beginRes.json();

      options.challenge = _b64uToBuffer(options.challenge);
      options.user.id   = _b64uToBuffer(options.user.id);
      if (options.excludeCredentials) {
        options.excludeCredentials = options.excludeCredentials.map((c) => ({
          ...c, id: _b64uToBuffer(c.id),
        }));
      }

      const credential = await navigator.credentials.create({ publicKey: options });
      if (!credential) throw new Error("Kein Credential erstellt");

      const completeRes = await fetch("/auth/register/complete", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ..._regCredToJSON(credential), label: keyLabel }),
      });
      const result = await completeRes.json();

      if (completeRes.ok) {
        window.location.href = "/auth/login?registered=1";
      } else {
        _showError(result.description || "Registrierung fehlgeschlagen");
      }
    } catch (err) {
      _showError(err.message || String(err));
    } finally {
      regBtn.disabled = false;
      regBtn.textContent = "Schlüssel registrieren";
    }
  });
}

function _b64uToBuffer(b) {
  const base64 = b.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0)).buffer;
}

function _bufToB64u(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function _regCredToJSON(c) {
  const r = c.response;
  return {
    id: c.id,
    rawId: _bufToB64u(c.rawId),
    type: c.type,
    transports: r.getTransports ? r.getTransports() : [],
    response: {
      attestationObject: _bufToB64u(r.attestationObject),
      clientDataJSON: _bufToB64u(r.clientDataJSON),
    },
  };
}

function _showError(msg) {
  let el = document.querySelector(".flash--error");
  if (!el) {
    el = document.createElement("div");
    el.className = "flash flash--error";
    regForm.before(el);
  }
  el.textContent = msg;
}
