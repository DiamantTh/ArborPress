const errorNode = document.getElementById("mfa-error");

function b64uToBuffer(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const bytes = Uint8Array.from(atob(normalized), (character) => character.charCodeAt(0));
  return bytes.buffer;
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

async function postJSON(url, payload) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(result.description || result.error || "Authentication failed");
  return result;
}

function showError(error) {
  errorNode.hidden = false;
  errorNode.textContent = error instanceof Error ? error.message : String(error);
}

document.getElementById("mfa-webauthn")?.addEventListener("click", async () => {
  try {
    const options = await postJSON("/auth/mfa/webauthn/begin", {});
    options.challenge = b64uToBuffer(options.challenge);
    options.allowCredentials?.forEach((credential) => {
      credential.id = b64uToBuffer(credential.id);
    });
    const assertion = await navigator.credentials.get({ publicKey: options });
    if (!assertion) throw new Error("No credential returned");
    await postJSON("/auth/mfa/webauthn/complete", credentialToJSON(assertion));
    window.location.href = "/admin";
  } catch (error) {
    showError(error);
  }
});

document.getElementById("mfa-totp-form")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await postJSON("/auth/mfa/totp/complete", {
      code: document.getElementById("totp-code").value.trim(),
    });
    window.location.href = "/admin";
  } catch (error) {
    showError(error);
  }
});
