const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || "";

function base64ToBytes(base64) {
  return Uint8Array.from(atob(base64), (ch) => ch.charCodeAt(0));
}

async function postJson(url, payload) {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": csrfToken,
    },
    body: JSON.stringify(payload),
  });
  let data = {};
  try {
    data = await response.json();
  } catch {
    data = {};
  }
  if (!response.ok) {
    throw new Error(data.error || `HTTP ${response.status}`);
  }
  return data;
}

function renderAssessment(target, data) {
  if (!target) {
    return;
  }
  const assessment = data.assessment || {};
  const policy = data.policy || {};
  const suggestions = Array.isArray(assessment.suggestions)
    ? assessment.suggestions.filter(Boolean)
    : [];
  const crackTime = assessment.crack_times_display?.offline_slow_hashing_1e4_per_second || "";
  target.innerHTML = `
    <div class="alert ${policy.accepted ? "alert-success" : "alert-warning"}">
      <strong>zxcvbn:</strong> ${assessment.score ?? 0}/4<br>
      <strong>Policy:</strong> ${policy.accepted ? "erfuellt" : "nicht erfuellt"}<br>
      ${policy.error ? `<div>${policy.error}</div>` : ""}
      ${assessment.warning ? `<div>${assessment.warning}</div>` : ""}
      ${suggestions.length ? `<div>${suggestions.join(" | ")}</div>` : ""}
      ${crackTime ? `<div>Offline-Angriff: ${crackTime}</div>` : ""}
    </div>
  `;
}

function setupStepup() {
  const button = document.getElementById("stepup-btn");
  if (!button) {
    return;
  }
  button.addEventListener("click", async () => {
    try {
      const beginRes = await postJson("/auth/stepup/begin", {});
      beginRes.publicKey.challenge = base64ToBytes(beginRes.publicKey.challenge);
      beginRes.publicKey.allowCredentials?.forEach((cred) => {
        cred.id = base64ToBytes(cred.id);
      });
      const assertion = await navigator.credentials.get({ publicKey: beginRes.publicKey });
      if (!assertion) {
        return;
      }
      const payload = {
        id: assertion.id,
        rawId: btoa(String.fromCharCode(...new Uint8Array(assertion.rawId))),
        response: {
          authenticatorData: btoa(String.fromCharCode(...new Uint8Array(assertion.response.authenticatorData))),
          clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(assertion.response.clientDataJSON))),
          signature: btoa(String.fromCharCode(...new Uint8Array(assertion.response.signature))),
        },
        type: assertion.type,
      };
      await postJson("/auth/stepup/complete", payload);
      window.location.reload();
    } catch {
      alert("Step-up fehlgeschlagen.");
    }
  });
}

function setupPasswordTools() {
  const panel = document.getElementById("password-tools");
  if (!panel) {
    return;
  }

  const mode = document.getElementById("pw-generator-mode");
  const words = document.getElementById("pw-generator-words");
  const delimiter = document.getElementById("pw-generator-delimiter");
  const length = document.getElementById("pw-generator-length");
  const xkcdFields = document.getElementById("pw-generator-xkcd-fields");
  const randomFields = document.getElementById("pw-generator-random-fields");
  const generateButton = document.getElementById("pw-generate-btn");
  const copyButton = document.getElementById("pw-copy-btn");
  const generated = document.getElementById("pw-generated");
  const evaluateInput = document.getElementById("pw-evaluate-input");
  const evaluateButton = document.getElementById("pw-evaluate-btn");
  const assessment = document.getElementById("pw-assessment");

  function syncMode() {
    const selected = mode.value;
    xkcdFields.hidden = selected !== "xkcd";
    randomFields.hidden = selected !== "random";
  }

  mode?.addEventListener("change", syncMode);
  syncMode();

  generateButton?.addEventListener("click", async () => {
    try {
      const data = await postJson("/admin/security/password-tools/generate", {
        mode: mode.value,
        words: Number(words.value || panel.dataset.defaultWords || 5),
        delimiter: delimiter.value || panel.dataset.defaultDelimiter || "-",
        length: Number(length.value || panel.dataset.defaultLength || 24),
      });
      generated.value = data.password || "";
      evaluateInput.value = data.password || "";
      renderAssessment(assessment, data);
    } catch (error) {
      alert(error.message);
    }
  });

  copyButton?.addEventListener("click", async () => {
    if (!generated.value) {
      return;
    }
    try {
      await navigator.clipboard.writeText(generated.value);
    } catch {
      alert("Kopieren fehlgeschlagen.");
    }
  });

  evaluateButton?.addEventListener("click", async () => {
    if (!evaluateInput.value) {
      return;
    }
    try {
      const data = await postJson("/admin/security/password-tools/evaluate", {
        password: evaluateInput.value,
      });
      renderAssessment(assessment, data);
    } catch (error) {
      alert(error.message);
    }
  });
}

setupStepup();
setupPasswordTools();