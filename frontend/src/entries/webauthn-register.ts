import { browserSupportsWebAuthn, startRegistration } from '@simplewebauthn/browser'

import { getResponseError, parseRegistrationOptions } from '../lib/webauthn.js'

function installRegistration(form: HTMLFormElement): void {
  const keyLabel = form.querySelector<HTMLInputElement>('#key_label')
  const securityKeyButton = form.querySelector<HTMLButtonElement>('#register-btn')
  const passkeyButton = form.querySelector<HTMLButtonElement>('#passkey-register-btn')
  const error = form.querySelector<HTMLElement>('[data-register-error]')
  const status = form.querySelector<HTMLElement>('[data-register-status]')
  if (!keyLabel || !securityKeyButton || !passkeyButton || !error || !status) return

  const supported = browserSupportsWebAuthn()
  securityKeyButton.disabled = !supported
  passkeyButton.disabled = !supported
  if (!supported) {
    status.textContent = 'Dieser Browser unterstützt WebAuthn nicht.'
    status.hidden = false
    return
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault()
    const submitter = event.submitter instanceof HTMLButtonElement ? event.submitter : securityKeyButton
    const enrollmentKind = submitter.value === 'passkey' ? 'passkey' : 'security_key'
    const label = keyLabel.value.trim() || 'Sicherheitsschlüssel'
    securityKeyButton.disabled = true
    passkeyButton.disabled = true
    error.hidden = true
    status.hidden = false
    status.textContent = 'Bitte den Authenticator bestätigen …'

    try {
      const beginResponse = await fetch('/auth/register/begin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enrollment_kind: enrollmentKind, label }),
      })
      if (!beginResponse.ok) throw await getResponseError(beginResponse, 'Registrierung konnte nicht gestartet werden.')
      const options = parseRegistrationOptions(await beginResponse.json())
      const credential = await startRegistration(options)
      const completeResponse = await fetch('/auth/register/complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...credential, label }),
      })
      if (!completeResponse.ok) throw await getResponseError(completeResponse, 'Registrierung ist fehlgeschlagen.')
      const result: unknown = await completeResponse.json()
      const recoveryOnly = typeof result === 'object' && result !== null
        && 'recovery_only' in result && result.recovery_only === true
      const successUrl = form.dataset.securityUrl
      window.location.assign(recoveryOnly && successUrl ? successUrl : form.dataset.loginUrl || '/auth/login?registered=1')
    } catch (caught: unknown) {
      error.hidden = false
      error.textContent = caught instanceof Error ? caught.message : 'Registrierung ist fehlgeschlagen.'
      status.hidden = true
    } finally {
      securityKeyButton.disabled = false
      passkeyButton.disabled = false
    }
  })
}

for (const form of document.querySelectorAll<HTMLFormElement>('#register-form')) {
  installRegistration(form)
}
