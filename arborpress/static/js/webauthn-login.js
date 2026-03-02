/**
 * WebAuthn Login – §2 primärer Auth-Pfad
 * Nutzt @simplewebauthn/browser wenn verfügbar,
 * sonst native navigator.credentials API.
 *
 * Dieses Modul wird als ES-Modul geladen (type="module").
 * §10: Kein CDN – muss lokal gebaut werden (npm run build im frontend/).
 */

const loginForm = document.getElementById("login-form");
const loginBtn  = document.getElementById("login-btn");

if (loginForm) {
  loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const userName = loginForm.querySelector("#user_name").value.trim();
    loginBtn.disabled = true;
    loginBtn.textContent = "Warte auf Schlüssel…";

    try {
      // 1: Challenge vom Server holen
      const beginRes = await fetch("/auth/login/begin", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user_name: userName }),
      });
      if (!beginRes.ok) throw new Error(await beginRes.text());
      const options = await beginRes.json();

      // 2: Browser-Credential-API
      options.challenge = _base64urlToBuffer(options.challenge);
      if (options.allowCredentials) {
        options.allowCredentials = options.allowCredentials.map((c) => ({
          ...c, id: _base64urlToBuffer(c.id),
        }));
      }

      const credential = await navigator.credentials.get({ publicKey: options });
      if (!credential) throw new Error("Kein Credential erhalten");

      // 3: Verifikation
      const completeRes = await fetch("/auth/login/complete", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(_credentialToJSON(credential)),
      });
      const result = await completeRes.json();

      if (completeRes.ok) {
        window.location.href = "/admin";
      } else {
        _showError(result.description || "Anmeldung fehlgeschlagen");
      }
    } catch (err) {
      _showError(err.message || String(err));
    } finally {
      loginBtn.disabled = false;
      loginBtn.textContent = "Mit Sicherheitsschlüssel anmelden";
    }
  });
}

function _base64urlToBuffer(base64url) {
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(base64);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer;
}

function _bufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let bin = "";
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function _credentialToJSON(credential) {
  const resp = credential.response;
  return {
    id: credential.id,
    rawId: _bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: _bufferToBase64url(resp.authenticatorData),
      clientDataJSON: _bufferToBase64url(resp.clientDataJSON),
      signature: _bufferToBase64url(resp.signature),
      userHandle: resp.userHandle ? _bufferToBase64url(resp.userHandle) : null,
    },
  };
}

function _showError(msg) {
  let el = document.querySelector(".flash--error");
  if (!el) {
    el = document.createElement("div");
    el.className = "flash flash--error";
    loginForm.before(el);
  }
  el.textContent = msg;
}
