<script lang="ts">
  interface Assessment {
    score?: number
    suggestions?: string[]
    warning?: string
    crack_times_display?: { offline_slow_hashing_1e4_per_second?: string }
  }

  interface PasswordResult {
    password?: string
    assessment?: Assessment
    policy?: { accepted?: boolean; error?: string }
  }

  export let generateUrl: string
  export let evaluateUrl: string

  let mode = 'random'
  let words = 6
  let delimiter = '-'
  let length = 24
  let generated = ''
  let evaluateValue = ''
  let result: PasswordResult | null = null
  let status = ''
  let error = ''
  let pending = false

  async function postJson(url: string, payload: Record<string, string | number>): Promise<PasswordResult> {
    const token = document.querySelector<HTMLMetaElement>('meta[name="csrf-token"]')?.content
    if (!token) throw new Error('CSRF-Token fehlt. Bitte die Seite neu laden.')

    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
      body: JSON.stringify(payload),
    })
    const data: unknown = await response.json().catch(() => ({}))
    if (!response.ok) {
      const message = typeof data === 'object' && data !== null && 'error' in data
        && typeof data.error === 'string' ? data.error : `HTTP ${response.status}`
      throw new Error(message)
    }
    return data as PasswordResult
  }

  async function run(action: () => Promise<void>): Promise<void> {
    pending = true
    error = ''
    status = ''
    try {
      await action()
    } catch (caught: unknown) {
      error = caught instanceof Error ? caught.message : 'Aktion fehlgeschlagen.'
    } finally {
      pending = false
    }
  }

  function acceptResult(data: PasswordResult): void {
    result = data
    status = 'Bewertung aktualisiert.'
  }

  function generate(): void {
    void run(async () => {
      const data = await postJson(generateUrl, { mode, words, delimiter, length })
      generated = data.password ?? ''
      evaluateValue = generated
      acceptResult(data)
    })
  }

  function evaluate(): void {
    if (!evaluateValue) return
    void run(async () => acceptResult(await postJson(evaluateUrl, { password: evaluateValue })))
  }

  async function copyPassword(): Promise<void> {
    if (!generated) return
    try {
      await navigator.clipboard.writeText(generated)
      status = 'Passwort in die Zwischenablage kopiert.'
      error = ''
    } catch {
      error = 'Kopieren fehlgeschlagen. Bitte das Passwort manuell auswählen.'
    }
  }
</script>

<section class="dashboard-card" aria-labelledby="password-tools-heading">
  <h3 id="password-tools-heading">Break-Glass Passwort-Werkzeuge</h3>
  <p>Diceware-Passphrasen und Zufallspasswörter werden mit der aktuellen Break-Glass-Policy bewertet.</p>

  <div class="admin-form">
    <label>
      Generator
      <select bind:value={mode}>
        <option value="random">Zufallspasswort</option>
        <option value="diceware">EFF Large Wordlist / Diceware</option>
      </select>
    </label>

    {#if mode === 'diceware'}
      <label>Wörter <input type="number" min="4" max="10" bind:value={words}></label>
      <label>Trenner <input type="text" maxlength="8" bind:value={delimiter}></label>
    {:else}
      <label>Länge <input type="number" min="16" max="256" bind:value={length}></label>
    {/if}

    <div class="form-actions">
      <button type="button" class="btn btn-primary" on:click={generate} disabled={pending}>
        {pending ? 'Bitte warten …' : 'Passwort generieren'}
      </button>
      <button type="button" class="btn" on:click={copyPassword} disabled={!generated}>
        In Zwischenablage kopieren
      </button>
    </div>

    <label>Generiertes Passwort <input type="text" readonly bind:value={generated} autocomplete="off"></label>
    <label>Eigenes Passwort prüfen <input type="password" bind:value={evaluateValue} autocomplete="new-password"></label>
    <button type="button" class="btn" on:click={evaluate} disabled={pending || !evaluateValue}>
      Qualität prüfen
    </button>

    {#if result}
      <div class:alert-success={result.policy?.accepted} class:alert-warning={!result.policy?.accepted} class="alert" role="status">
        <strong>zxcvbn:</strong> {result.assessment?.score ?? 0}/4<br>
        <strong>Policy:</strong> {result.policy?.accepted ? 'erfüllt' : 'nicht erfüllt'}
        {#if result.policy?.error}<p>{result.policy.error}</p>{/if}
        {#if result.assessment?.warning}<p>{result.assessment.warning}</p>{/if}
        {#if result.assessment?.suggestions?.length}<p>{result.assessment.suggestions.join(' | ')}</p>{/if}
        {#if result.assessment?.crack_times_display?.offline_slow_hashing_1e4_per_second}
          <p>Offline-Angriff: {result.assessment.crack_times_display.offline_slow_hashing_1e4_per_second}</p>
        {/if}
      </div>
    {/if}
    {#if status}<p role="status" aria-live="polite">{status}</p>{/if}
    {#if error}<p class="alert alert-danger" role="alert" aria-live="assertive">{error}</p>{/if}
    <p>CLI: <code>arborpress user password-generate --generator diceware</code></p>
  </div>
</section>
