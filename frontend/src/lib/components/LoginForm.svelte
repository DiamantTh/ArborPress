<script lang="ts">
  import { onMount } from 'svelte'
  import { browserSupportsWebAuthn, startAuthentication } from '@simplewebauthn/browser'
  import { getResponseError, parseAuthenticationOptions } from '../webauthn.js'

  export let loginRoot: HTMLElement

  let status = ''
  let error = ''

  onMount(() => {
    const form = loginRoot.querySelector<HTMLFormElement>('[data-ap-webauthn-form]')
    const identifier = loginRoot.querySelector<HTMLInputElement>('#user_name')
    const button = loginRoot.querySelector<HTMLButtonElement>('#login-btn')
    if (!form || !identifier || !button) return

    if (!browserSupportsWebAuthn()) {
      error = 'Dieser Browser unterstützt WebAuthn nicht.'
      return
    }

    button.disabled = false

    const handleLogin = async (event: SubmitEvent) => {
      event.preventDefault()
      if (!identifier.reportValidity()) return
      status = 'Passkey wird abgefragt …'
      error = ''
      identifier.disabled = true
      button.disabled = true

      try {
        const beginResponse = await fetch('/auth/login/begin', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ identifier: identifier.value.trim() }),
        })
        if (!beginResponse.ok) {
          throw await getResponseError(beginResponse, 'Anmeldung fehlgeschlagen.')
        }

        const options = parseAuthenticationOptions(await beginResponse.json())
        const credential = await startAuthentication(options)
        const completeResponse = await fetch('/auth/login/complete', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(credential),
        })
        if (!completeResponse.ok) {
          throw await getResponseError(completeResponse, 'Anmeldung fehlgeschlagen.')
        }

        status = 'Erfolgreich angemeldet. Weiterleitung …'
        window.location.assign(loginRoot.dataset.successUrl || '/admin')
      } catch (caught: unknown) {
        error = caught instanceof Error ? caught.message : 'Anmeldung fehlgeschlagen.'
        status = ''
        identifier.focus()
      } finally {
        identifier.disabled = false
        button.disabled = false
      }
    }

    form.addEventListener('submit', handleLogin)
    return () => form.removeEventListener('submit', handleLogin)
  })
</script>

{#if status}<p class="auth-box__hint" role="status" aria-live="polite">{status}</p>{/if}
{#if error}<p class="flash flash--error" role="alert" aria-live="assertive">{error}</p>{/if}

<style>
  p { margin-block: 0.75rem; }
</style>
