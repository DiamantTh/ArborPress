<script lang="ts">
  import { startAuthentication } from '@simplewebauthn/browser';

  let identifier = '';
  let status = '';
  let error = '';

  async function handleLogin() {
    error = '';
    if (!identifier.trim()) {
      error = 'Benutzername oder E-Mail erforderlich.';
      return;
    }
    status = 'Passkey abfragen …';
    try {
      const beginRes = await fetch('/auth/login/begin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identifier: identifier.trim() }),
      });
      if (!beginRes.ok) throw new Error('Anmeldung fehlgeschlagen.');
      const opts = await beginRes.json();

      const credential = await startAuthentication(opts);

      const completeRes = await fetch('/auth/login/complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credential),
      });
      if (completeRes.ok) {
        status = 'Erfolgreich angemeldet.';
        window.location.href = '/';
      } else {
        error = 'Anmeldung fehlgeschlagen.';
        status = '';
      }
    } catch (e: unknown) {
      error = e instanceof Error ? e.message : String(e);
      status = '';
    }
  }

</script>

<div class="card">
  <label>
    Benutzername oder E-Mail
    <input bind:value={identifier} autocomplete="username" required />
  </label>
  <button class="passkey-btn" on:click={handleLogin}>
    🔑 Mit FIDO2-Schlüssel oder Passkey anmelden
  </button>

  {#if status}<p class="info">{status}</p>{/if}
  {#if error}<p class="err">{error}</p>{/if}
</div>

<style>
  .card {
    background: #fff;
    border: 1px solid #e0e0e0;
    border-radius: 12px;
    padding: 2rem;
    width: 360px;
    display: flex;
    flex-direction: column;
    gap: 1rem;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
  }

  label {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    font-size: 0.875rem;
  }

  input {
    border: 1px solid #ccc;
    border-radius: 6px;
    padding: 0.5rem;
    font-size: 1rem;
  }

  .passkey-btn {
    padding: 0.75rem;
    background: #1a1a2e;
    color: #fff;
    border: none;
    border-radius: 8px;
    font-size: 1rem;
    cursor: pointer;
  }

  .passkey-btn:hover {
    background: #2d2d5e;
  }

  .info {
    color: #2a7d4f;
    font-size: 0.875rem;
  }

  .err {
    color: #c0392b;
    font-size: 0.875rem;
  }
</style>
