import '../../../arborpress/static/css/admin.css'
import AdminCaptchaQuestions from '../lib/components/AdminCaptchaQuestions.svelte'
import AdminPasswordTools from '../lib/components/AdminPasswordTools.svelte'
import { parseCaptchaQuestions } from '../lib/admin-data.js'
import { parseAuthenticationOptions } from '../lib/webauthn.js'
import { startAuthentication } from '@simplewebauthn/browser'

interface JsonRecord {
  [key: string]: unknown
}

async function postJson(url: string, payload: unknown): Promise<JsonRecord> {
  const token = document.querySelector<HTMLMetaElement>('meta[name="csrf-token"]')?.content
  if (!token) throw new Error('CSRF-Token fehlt. Bitte die Seite neu laden.')

  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
    body: JSON.stringify(payload),
  })
  const data: unknown = await response.json().catch(() => ({}))
  if (!response.ok) {
    if (typeof data === 'object' && data !== null && !Array.isArray(data)) {
      const record = data as JsonRecord
      for (const key of ['description', 'message', 'error']) {
        if (typeof record[key] === 'string' && record[key]) {
          throw new Error(record[key])
        }
      }
    }
    throw new Error(`Aktion fehlgeschlagen (HTTP ${response.status}).`)
  }
  if (typeof data !== 'object' || data === null || Array.isArray(data)) return {}
  return data as JsonRecord
}

function feedback(message: string, isError = false): void {
  let target = document.querySelector<HTMLElement>('[data-admin-feedback]')
  if (!target) {
    target = document.createElement('div')
    target.dataset.adminFeedback = ''
    target.className = 'flash'
    document.querySelector('main')?.prepend(target)
  }
  target.hidden = false
  target.setAttribute('role', isError ? 'alert' : 'status')
  target.setAttribute('aria-live', isError ? 'assertive' : 'polite')
  target.textContent = message
}

async function authenticateStepup(action: string, target: string): Promise<void> {
  const options = await postJson('/auth/stepup/begin', { action, target })
  const credential = await startAuthentication(parseAuthenticationOptions(options))
  await postJson('/auth/stepup/complete', credential)
}

function installStepup(): void {
  const button = document.getElementById('stepup-btn') as HTMLButtonElement | null
  button?.addEventListener('click', async () => {
    button.disabled = true
    try {
      await authenticateStepup(button.dataset.action || 'change_security_settings', button.dataset.target || 'instance')
      window.location.reload()
    } catch {
      feedback('Step-up fehlgeschlagen. Bitte erneut versuchen.', true)
    } finally {
      button.disabled = false
    }
  })

  for (const form of document.querySelectorAll<HTMLFormElement>('form[data-stepup-action]')) {
    form.addEventListener('submit', async (event) => {
      if (form.dataset.stepupActive === 'true') return
      if (form.dataset.stepupPassed === 'true') {
        delete form.dataset.stepupPassed
        return
      }
      event.preventDefault()
      const submitter = event.submitter instanceof HTMLElement ? event.submitter : undefined
      try {
        await authenticateStepup(form.dataset.stepupAction || '', form.dataset.stepupTarget || 'instance')
        form.dataset.stepupPassed = 'true'
        form.requestSubmit(submitter)
      } catch {
        feedback('Step-up fehlgeschlagen. Die Aktion wurde nicht ausgeführt.', true)
      }
    })
  }
}

function installPluginActions(): void {
  for (const button of document.querySelectorAll<HTMLButtonElement>('.plugin-toggle')) {
    button.disabled = false
    button.addEventListener('click', async () => {
      const url = button.dataset.url
      if (!url) return
      button.disabled = true
      try {
        try {
          await postJson(url, {})
        } catch (error: unknown) {
          if (!(error instanceof Error) || error.message !== 'step_up_required') throw error
          await authenticateStepup(button.dataset.stepupAction || '', button.dataset.stepupTarget || '')
          await postJson(url, {})
        }
        feedback('Plugin-Aktion wurde vom Server bestätigt.')
        window.location.reload()
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : 'Plugin-Aktion fehlgeschlagen.'
        feedback(message.includes('step_up_required')
          ? 'Für diese Aktion ist eine erneute Step-up-Authentifizierung erforderlich.'
          : message, true)
      } finally {
        button.disabled = false
      }
    })
  }
}

function installMediaCopy(): void {
  for (const button of document.querySelectorAll<HTMLButtonElement>('.copy-url')) {
    button.disabled = false
    button.addEventListener('click', async () => {
      const url = button.dataset.url
      if (!url) return
      const status = button.parentElement?.querySelector<HTMLElement>('.copy-url-status')
      try {
        await navigator.clipboard.writeText(new URL(url, window.location.href).href)
        if (status) status.textContent = 'Kopiert.'
      } catch {
        if (status) status.textContent = 'Kopieren nicht möglich; URL bitte über den Link öffnen.'
      }
    })
  }
}

function installConfirmations(): void {
  document.addEventListener('submit', (event) => {
    const form = event.target
    if (!(form instanceof HTMLFormElement)) return
    const submitter = event.submitter
    const message = submitter instanceof HTMLElement
      ? submitter.dataset.confirm || form.dataset.confirm
      : form.dataset.confirm
    if (message && !window.confirm(message)) event.preventDefault()
  }, true)
}

function mountCaptchaQuestions(): void {
  const root = document.querySelector<HTMLElement>('[data-ap-admin-mount="captcha-questions"]')
  const fallback = document.getElementById('questions-list-fallback')
  const source = document.getElementById('captcha-questions-data')
  if (!root || !fallback || !source) return
  try {
    const questions = parseCaptchaQuestions(source.textContent || '[]')
    new AdminCaptchaQuestions({ target: root, props: { initialQuestions: questions } })
    root.hidden = false
    fallback.hidden = true
  } catch {
    feedback('Die Fragenliste konnte nicht interaktiv geladen werden; die serverseitig gerenderte Liste bleibt verfügbar.', true)
  }
}

function mountPasswordTools(): void {
  const root = document.querySelector<HTMLElement>('[data-ap-admin-mount="password-tools"]')
  if (!root) return
  const fallback = root.querySelector<HTMLElement>('[data-admin-fallback]')
  const mountPoint = root.querySelector<HTMLElement>('[data-admin-mount-point]')
  const generateUrl = root.dataset.generateUrl
  const evaluateUrl = root.dataset.evaluateUrl
  if (!mountPoint || !generateUrl || !evaluateUrl) return
  new AdminPasswordTools({ target: mountPoint, props: { generateUrl, evaluateUrl } })
  if (fallback) fallback.hidden = true
}

installStepup()
installPluginActions()
installMediaCopy()
installConfirmations()
mountCaptchaQuestions()
mountPasswordTools()
