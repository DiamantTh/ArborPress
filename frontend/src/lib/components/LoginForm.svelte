<script lang="ts">
  import {
    startAuthentication,
    startRegistration,
  } from '@simplewebauthn/browser';

  let mode: 'login' | 'register' = 'login';
  let userName = '';
  let displayName = '';
  let status = '';
  let error = '';

  async function handleLogin() {
    error = '';
    status = 'Passkey abfragen …';
    try {
      const beginRes = await fetch('/auth/login/begin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
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

  async function handleRegister() {
    error = '';
    status = 'Passkey erstellen …';
    try {
      const beginRes = await fetch('/auth/register/begin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_name: userName, display_name: displayName }),
      });
      const opts = await beginRes.json();

      const credential = await startRegistration(opts);

      const completeRes = await fetch('/auth/register/complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credential),
      });
      if (completeRes.ok) {
        status = 'Passkey registriert. Du kannst dich jetzt anmelden.';
        mode = 'login';
      } else {
        error = 'Registrierung fehlgeschlagen.';
        status = '';
      }
    } catch (e: unknown) {
      error = e instanceof Error ? e.message : String(e);
      status = '';
    }
  }
</script>

<div class="card">
  <nav>
    <button class:active={mode === 'login'} on:click={() => (mode = 'login')}>Anmelden</button>
    <button class:active={mode === 'register'} on:click={() => (mode = 'register')}>
      Registrieren
    </button>
  </nav>

  {#if mode === 'login'}
    <button class="passkey-btn" on:click={handleLogin}>
      🔑 Mit Passkey anmelden
    </button>
  {:else}
    <label>
      Benutzername
      <input bind:value={userName} placeholder="alice" autocomplete="username" />
    </label>
    <label>
      Anzeigename
      <input bind:value={displayName} placeholder="Alice Beispiel" autocomplete="name" />
    </label>
    <button class="passkey-btn" on:click={handleRegister}>
      🔑 Passkey erstellen
    </button>
  {/if}

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

  nav {
    display: flex;
    gap: 0.5rem;
  }

  nav button {
    flex: 1;
    padding: 0.5rem;
    border: 1px solid #ccc;
    border-radius: 6px;
    background: #f5f5f5;
    cursor: pointer;
  }

  nav button.active {
    background: #1a1a2e;
    color: #fff;
    border-color: #1a1a2e;
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
