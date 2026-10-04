const errorNode = document.getElementById("security-error");

function b64uToBuffer(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(normalized), (character) => character.charCodeAt(0)).buffer;
}

function bufferToB64u(value) {
  const bytes = new Uint8Array(value);
  let binary = "";
  bytes.forEach((byte) => (binary += String.fromCharCode(byte)));
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function credentialToJSON(credential) {
  const response = credential.response;
  return {
    id: credential.id,
    rawId: bufferToB64u(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: bufferToB64u(response.authenticatorData),
      clientDataJSON: bufferToB64u(response.clientDataJSON),
      signature: bufferToB64u(response.signature),
      userHandle: response.userHandle ? bufferToB64u(response.userHandle) : null,
    },
  };
}

async function postJSON(url, payload = {}) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.description || data.error || `HTTP ${response.status}`);
  return data;
}

function showError(error) {
  errorNode.hidden = false;
  errorNode.textContent = error instanceof Error ? error.message : String(error);
}

async function authenticateWithTotp() {
  const code = window.prompt("Gib den aktuellen Code eines aktiven TOTP-Authenticators ein:");
  if (!code) throw new Error("TOTP-Bestätigung abgebrochen");
  await postJSON("/auth/stepup/totp/complete", { code: code.trim() });
}

async function restartForTotp(action, target) {
  const options = await postJSON("/auth/stepup/begin", { action, target });
  if (!options.totp_only && !options.totp_available) {
    throw new Error("Für diese Aktion ist kein TOTP-Fallback verfügbar");
  }
  await authenticateWithTotp();
}

async function authenticateFor(action, target, { allowTotp = false } = {}) {
  const options = await postJSON("/auth/stepup/begin", { action, target });
  if (options.totp_only) {
    if (!allowTotp) throw new Error("Für diese Aktion ist FIDO2-Step-up erforderlich");
    await authenticateWithTotp();
    return;
  }
  options.challenge = b64uToBuffer(options.challenge);
  options.allowCredentials?.forEach((credential) => {
    credential.id = b64uToBuffer(credential.id);
  });
  let assertion;
  try {
    assertion = await navigator.credentials.get({ publicKey: options });
  } catch (error) {
    if (!allowTotp || !options.totp_available) throw error;
    await restartForTotp(action, target);
    return;
  }
  if (!assertion) throw new Error("No authenticator response returned");
  try {
    await postJSON("/auth/stepup/complete", credentialToJSON(assertion));
  } catch (error) {
    if (!allowTotp || !options.totp_available) throw error;
    await restartForTotp(action, target);
  }
}

document.querySelectorAll(".stepup-redirect").forEach((button) => {
  button.addEventListener("click", async () => {
    try {
      await authenticateFor(button.dataset.action, button.dataset.target, {
        allowTotp: button.dataset.allowTotp === "true",
      });
      window.location.href = button.dataset.next;
    } catch (error) {
      showError(error);
    }
  });
});

document.getElementById("totp-add")?.addEventListener("click", async (event) => {
  const button = event.currentTarget;
  try {
    if (button.dataset.recoveryOnly !== "true") {
      await authenticateFor(button.dataset.action, button.dataset.target);
    }
    const enrollment = await postJSON("/auth/totp/begin", { label: "Authenticator" });
    document.getElementById("totp-uri").textContent = enrollment.provisioning_uri;
    document.getElementById("totp-enrollment").hidden = false;
    document.getElementById("totp-confirm-code").focus();
  } catch (error) {
    showError(error);
  }
});

document.getElementById("totp-confirm-form")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await postJSON("/auth/totp/complete", {
      code: document.getElementById("totp-confirm-code").value.trim(),
    });
    window.location.reload();
  } catch (error) {
    showError(error);
  }
});

document.querySelectorAll(".stepup-remove").forEach((button) => {
  button.addEventListener("click", async () => {
    try {
      await authenticateFor(button.dataset.action, button.dataset.target);
      const response = await fetch(button.dataset.url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
      if (!response.ok) throw new Error((await response.json()).description || "Removal failed");
      window.location.reload();
    } catch (error) {
      showError(error);
    }
  });
});

document.querySelectorAll(".recovery-remove").forEach((button) => {
  button.addEventListener("click", async () => {
    try {
      const response = await fetch(button.dataset.url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(data.description || data.error || "Removal failed");
      }
      window.location.reload();
    } catch (error) {
      showError(error);
    }
  });
});

document.getElementById("recovery-complete")?.addEventListener("click", async () => {
  try {
    await postJSON("/auth/recovery/complete");
    window.location.href = "/auth/login?recovery=complete";
  } catch (error) {
    showError(error);
  }
});
