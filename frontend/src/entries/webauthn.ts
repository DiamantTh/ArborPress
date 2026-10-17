import LoginForm from '../lib/components/LoginForm.svelte'

// This is an island entry only: Quart owns the URL and renders the surrounding HTML.
// It is intentionally not mounted until a Jinja page opts into this data attribute.
for (const target of document.querySelectorAll<HTMLElement>('[data-ap-webauthn-login]')) {
  new LoginForm({ target })
}
