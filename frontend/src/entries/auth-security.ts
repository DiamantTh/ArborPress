import { startAuthentication } from '@simplewebauthn/browser'

import { parseAuthenticationOptions, postAuthJson } from '../lib/webauthn.js'

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback
}

function showError(target: HTMLElement, error: unknown, fallback: string): void {
  target.hidden = false
  target.textContent = errorMessage(error, fallback)
}

function installSecurity(root: HTMLElement): void {
  const error = root.querySelector<HTMLElement>('[data-auth-error]')
  const showFailure = (caught: unknown, fallback: string): void => {
    if (error) showError(error, caught, fallback)
  }

  const authenticateWithTotp = async (): Promise<void> => {
    const code = window.prompt('Gib den aktuellen Code eines aktiven TOTP-Authenticators ein:')
    if (!code) throw new Error('TOTP-Bestätigung abgebrochen.')
    await postAuthJson('/auth/stepup/totp/complete', { code: code.trim() }, 'TOTP-Bestätigung fehlgeschlagen.')
  }

  const authenticateFor = async (
    action: string,
    target: string,
    allowTotp = false,
  ): Promise<void> => {
    const options = await postAuthJson('/auth/stepup/begin', { action, target }, 'Step-up konnte nicht gestartet werden.')
    if (options.totp_only === true) {
      if (!allowTotp) throw new Error('Für diese Aktion ist FIDO2-Step-up erforderlich.')
      await authenticateWithTotp()
      return
    }

    try {
      const credential = await startAuthentication(parseAuthenticationOptions(options))
      await postAuthJson('/auth/stepup/complete', credential, 'Step-up ist fehlgeschlagen.')
    } catch (caught: unknown) {
      if (!allowTotp || options.totp_available !== true) throw caught

      // Starting a new step-up challenge preserves the server's current policy
      // and prevents a stale or unrelated TOTP flow from being reused.
      const fallback = await postAuthJson('/auth/stepup/begin', { action, target }, 'TOTP-Step-up konnte nicht gestartet werden.')
      if (fallback.totp_only !== true && fallback.totp_available !== true) {
        throw new Error('Für diese Aktion ist kein TOTP-Fallback verfügbar.')
      }
      await authenticateWithTotp()
    }
  }

  for (const button of root.querySelectorAll<HTMLButtonElement>('.stepup-redirect')) {
    button.addEventListener('click', async () => {
      button.disabled = true
      if (error) error.hidden = true
      try {
        const action = button.dataset.action
        const target = button.dataset.target
        const next = button.dataset.next
        if (!action || !target || !next) throw new Error('Die Aktion ist unvollständig konfiguriert.')
        await authenticateFor(action, target, button.dataset.allowTotp === 'true')
        window.location.assign(next)
      } catch (caught: unknown) {
        showFailure(caught, 'Step-up ist fehlgeschlagen.')
      } finally {
        button.disabled = false
      }
    })
    button.disabled = false
  }

  const addTotp = root.querySelector<HTMLButtonElement>('#totp-add')
  addTotp?.addEventListener('click', async () => {
    addTotp.disabled = true
    if (error) error.hidden = true
    try {
      const action = addTotp.dataset.action
      const target = addTotp.dataset.target
      if (!action || !target) throw new Error('Die Aktion ist unvollständig konfiguriert.')
      if (addTotp.dataset.recoveryOnly !== 'true') await authenticateFor(action, target)
      const enrollment = await postAuthJson('/auth/totp/begin', { label: 'Authenticator' }, 'TOTP-Einrichtung konnte nicht gestartet werden.')
      const uri = root.querySelector<HTMLElement>('#totp-uri')
      const panel = root.querySelector<HTMLElement>('#totp-enrollment')
      const code = root.querySelector<HTMLInputElement>('#totp-confirm-code')
      if (typeof enrollment.provisioning_uri !== 'string' || !uri || !panel || !code) {
        throw new Error('Der Server hat ungültige TOTP-Einrichtungsdaten geliefert.')
      }
      uri.textContent = enrollment.provisioning_uri
      panel.hidden = false
      code.focus()
    } catch (caught: unknown) {
      showFailure(caught, 'TOTP-Einrichtung konnte nicht gestartet werden.')
    } finally {
      addTotp.disabled = false
    }
  })
  if (addTotp) addTotp.disabled = false

  const confirmationForm = root.querySelector<HTMLFormElement>('#totp-confirm-form')
  confirmationForm?.addEventListener('submit', async (event) => {
    event.preventDefault()
    const code = confirmationForm.querySelector<HTMLInputElement>('#totp-confirm-code')
    const submit = confirmationForm.querySelector<HTMLButtonElement>('button[type="submit"]')
    if (!code || !submit || !code.reportValidity()) return
    submit.disabled = true
    if (error) error.hidden = true
    try {
      await postAuthJson('/auth/totp/complete', { code: code.value.trim() }, 'Der Authenticator-Code wurde nicht akzeptiert.')
      window.location.reload()
    } catch (caught: unknown) {
      showFailure(caught, 'Der Authenticator-Code wurde nicht akzeptiert.')
      code.focus()
    } finally {
      submit.disabled = false
    }
  })

  for (const button of root.querySelectorAll<HTMLButtonElement>('.stepup-remove, .recovery-remove')) {
    button.addEventListener('click', async () => {
      const url = button.dataset.url
      if (!url) return
      button.disabled = true
      if (error) error.hidden = true
      try {
        if (button.matches('.stepup-remove')) {
          const action = button.dataset.action
          const target = button.dataset.target
          if (!action || !target) throw new Error('Die Aktion ist unvollständig konfiguriert.')
          await authenticateFor(action, target, button.dataset.allowTotp === 'true')
        }
        await postAuthJson(url, {}, 'Credential konnte nicht entfernt werden.')
        window.location.reload()
      } catch (caught: unknown) {
        showFailure(caught, 'Credential konnte nicht entfernt werden.')
      } finally {
        button.disabled = false
      }
    })
    button.disabled = false
  }

  const recoveryComplete = root.querySelector<HTMLButtonElement>('#recovery-complete')
  recoveryComplete?.addEventListener('click', async () => {
    recoveryComplete.disabled = true
    if (error) error.hidden = true
    try {
      await postAuthJson('/auth/recovery/complete', {}, 'Recovery konnte nicht abgeschlossen werden.')
      window.location.assign('/auth/login?recovery=complete')
    } catch (caught: unknown) {
      showFailure(caught, 'Recovery konnte nicht abgeschlossen werden.')
    } finally {
      recoveryComplete.disabled = false
    }
  })
  if (recoveryComplete) recoveryComplete.disabled = false
}

for (const root of document.querySelectorAll<HTMLElement>('[data-ap-auth-security]')) {
  installSecurity(root)
}
