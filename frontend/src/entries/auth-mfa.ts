import { browserSupportsWebAuthn, startAuthentication } from '@simplewebauthn/browser'

import { parseAuthenticationOptions, postAuthJson } from '../lib/webauthn.js'

function showError(target: HTMLElement, error: unknown, fallback: string): void {
  target.hidden = false
  target.textContent = error instanceof Error ? error.message : fallback
}

function installMfa(root: HTMLElement): void {
  const error = root.querySelector<HTMLElement>('[data-auth-error]')
  const successUrl = root.dataset.successUrl || '/admin'
  const webauthnButton = root.querySelector<HTMLButtonElement>('#mfa-webauthn')
  const totpForm = root.querySelector<HTMLFormElement>('#mfa-totp-form')

  if (webauthnButton) {
    webauthnButton.disabled = !browserSupportsWebAuthn()
    webauthnButton.addEventListener('click', async () => {
      webauthnButton.disabled = true
      if (error) error.hidden = true
      try {
        const options = await postAuthJson(
          '/auth/mfa/webauthn/begin',
          {},
          'Die zweite Authentifizierung konnte nicht gestartet werden.',
        )
        const credential = await startAuthentication(parseAuthenticationOptions(options))
        await postAuthJson(
          '/auth/mfa/webauthn/complete',
          credential,
          'Die zweite Authentifizierung ist fehlgeschlagen.',
        )
        window.location.assign(successUrl)
      } catch (caught: unknown) {
        if (error) showError(error, caught, 'Die zweite Authentifizierung ist fehlgeschlagen.')
      } finally {
        webauthnButton.disabled = !browserSupportsWebAuthn()
      }
    })
  }

  if (totpForm) {
    const codeInput = totpForm.querySelector<HTMLInputElement>('#totp-code')
    const submit = totpForm.querySelector<HTMLButtonElement>('button[type="submit"]')
    if (codeInput && submit) {
      codeInput.required = true
      submit.disabled = false
      totpForm.addEventListener('submit', async (event) => {
        event.preventDefault()
        if (!codeInput.reportValidity()) return
        submit.disabled = true
        if (error) error.hidden = true
        try {
          await postAuthJson(
            '/auth/mfa/totp/complete',
            { code: codeInput.value.trim() },
            'Der Authenticator-Code wurde nicht akzeptiert.',
          )
          window.location.assign(successUrl)
        } catch (caught: unknown) {
          if (error) showError(error, caught, 'Der Authenticator-Code wurde nicht akzeptiert.')
          codeInput.focus()
        } finally {
          submit.disabled = false
        }
      })
    }
  }
}

for (const root of document.querySelectorAll<HTMLElement>('[data-ap-auth-mfa]')) {
  installMfa(root)
}
