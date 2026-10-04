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

async function authenticateFor(action, target) {
  const options = await postJSON("/auth/stepup/begin", { action, target });
  options.challenge = b64uToBuffer(options.challenge);
  options.allowCredentials?.forEach((credential) => {
    credential.id = b64uToBuffer(credential.id);
  });
  const assertion = await navigator.credentials.get({ publicKey: options });
  if (!assertion) throw new Error("No authenticator response returned");
  await postJSON("/auth/stepup/complete", credentialToJSON(assertion));
}

document.querySelectorAll(".stepup-redirect").forEach((button) => {
  button.addEventListener("click", async () => {
    try {
      await authenticateFor(button.dataset.action, button.dataset.target);
      window.location.href = button.dataset.next;
    } catch (error) {
      showError(error);
    }
  });
});

document.getElementById("totp-add")?.addEventListener("click", async (event) => {
  const button = event.currentTarget;
  try {
    await authenticateFor(button.dataset.action, button.dataset.target);
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
