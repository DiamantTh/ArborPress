function storageGet(key: string): string | null {
  try {
    return window.localStorage.getItem(key)
  } catch {
    return null
  }
}

function storageSet(key: string, value: string): void {
  try {
    window.localStorage.setItem(key, value)
  } catch {
    // Privacy settings can disable local storage; the current page still works.
  }
}

function installFlashDismissal(): void {
  for (const flash of document.querySelectorAll<HTMLElement>('.flash')) {
    window.setTimeout(() => {
      flash.style.transition = 'opacity .4s'
      flash.style.opacity = '0'
      window.setTimeout(() => flash.remove(), 400)
    }, 5000)
  }
}

function installColorScheme(): void {
  const light = document.getElementById('ap-theme-css') as HTMLLinkElement | null
  const dark = document.getElementById('ap-theme-dark-css') as HTMLLinkElement | null
  if (!light || !dark) return

  const button = document.getElementById('ap-dark-toggle')
  const icon = document.getElementById('ap-toggle-icon')
  const html = document.documentElement

  const apply = (useDark: boolean): void => {
    dark.disabled = !useDark
    light.disabled = useDark
    if (icon) icon.textContent = useDark ? '☀️' : '🌙'
    html.setAttribute('data-scheme', useDark ? 'dark' : 'light')
  }

  const stored = storageGet('ap-color-scheme')
  apply(stored === 'dark' || (
    stored === null && window.matchMedia('(prefers-color-scheme: dark)').matches
  ))

  button?.addEventListener('click', () => {
    const useDark = dark.disabled
    apply(useDark)
    storageSet('ap-color-scheme', useDark ? 'dark' : 'light')
  })

  const oledButton = document.getElementById('ap-oled-toggle')
  if (!oledButton) return

  const applyOled = (enabled: boolean): void => {
    if (enabled) html.setAttribute('data-oled', '')
    else html.removeAttribute('data-oled')
    oledButton.classList.toggle('active', enabled)
    storageSet('ap-oled', enabled ? '1' : '0')
  }
  const syncOledVisibility = (): void => {
    const isDark = html.getAttribute('data-scheme') === 'dark'
    oledButton.hidden = !isDark
    if (!isDark) {
      html.removeAttribute('data-oled')
      oledButton.classList.remove('active')
    }
  }

  applyOled(storageGet('ap-oled') === '1')
  syncOledVisibility()
  oledButton.addEventListener('click', () => {
    applyOled(!html.hasAttribute('data-oled'))
  })
  new MutationObserver(syncOledVisibility).observe(html, {
    attributes: true,
    attributeFilter: ['data-scheme'],
  })
}

function installDemoThemePanel(): void {
  const panel = document.getElementById('ap-demo-panel')
  const toggle = document.getElementById('ap-demo-toggle') as HTMLButtonElement | null
  const inner = document.getElementById('ap-demo-inner')
  const label = document.getElementById('ap-demo-label')
  const light = document.getElementById('ap-theme-css') as HTMLLinkElement | null
  const dark = document.getElementById('ap-theme-dark-css') as HTMLLinkElement | null
  if (!panel || !toggle || !inner) return

  const buttons = [...inner.querySelectorAll<HTMLButtonElement>('[data-id]')]
  const saveThemeCookie = (id: string): void => {
    document.cookie = `ap-theme=${encodeURIComponent(id)}; path=/; max-age=31536000; SameSite=Lax`
  }

  const applyTheme = (button: HTMLButtonElement): void => {
    const id = button.dataset.id
    const lightUrl = button.dataset.light
    if (!id || !lightUrl) return

    if (light) light.href = lightUrl
    const darkUrl = button.dataset.dark
    if (dark && darkUrl) {
      dark.href = darkUrl
      const useDark = storageGet('ap-color-scheme') === 'dark'
      dark.disabled = !useDark
      if (light) light.disabled = useDark
    } else if (dark) {
      dark.href = ''
      dark.disabled = true
      if (light) light.disabled = false
    }

    const icon = document.getElementById('ap-toggle-icon')
    if (icon) icon.textContent = dark && !dark.disabled ? '☀️' : '🌙'
    storageSet('ap-theme', id)
    saveThemeCookie(id)
    if (label) label.textContent = button.textContent?.trim() ?? id
    for (const item of buttons) item.classList.toggle('is-active', item.dataset.id === id)
  }

  toggle.addEventListener('click', (event) => {
    event.stopPropagation()
    inner.hidden = !inner.hidden
    toggle.setAttribute('aria-expanded', String(!inner.hidden))
  })
  document.addEventListener('click', (event) => {
    if (event.target instanceof Node && !panel.contains(event.target)) {
      inner.hidden = true
      toggle.setAttribute('aria-expanded', 'false')
    }
  })
  for (const button of buttons) {
    button.addEventListener('click', (event) => {
      event.stopPropagation()
      applyTheme(button)
      inner.hidden = true
      toggle.setAttribute('aria-expanded', 'false')
    })
  }

  const stored = storageGet('ap-theme')
  const selected = buttons.find((button) => button.dataset.id === stored)
  if (selected) applyTheme(selected)
}

installFlashDismissal()
installColorScheme()
installDemoThemePanel()
