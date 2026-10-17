import LoginForm from '../lib/components/LoginForm.svelte'

// Quart/Jinja render the login controls. Svelte only attaches WebAuthn behavior
// and live feedback to the existing server-rendered island.
for (const root of document.querySelectorAll<HTMLElement>('[data-ap-webauthn-login]')) {
  const feedback = root.querySelector<HTMLElement>('[data-ap-webauthn-feedback]')
  if (feedback) {
    new LoginForm({ target: feedback, props: { loginRoot: root } })
  }
}
