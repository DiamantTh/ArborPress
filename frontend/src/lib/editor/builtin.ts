export type MarkdownAction =
  | { type: 'wrap'; before: string; after: string; sample: string }
  | { type: 'block'; text: string }
  | { type: 'line-prefix'; prefix: string }

export interface SelectionEdit {
  value: string
  selectionStart: number
  selectionEnd: number
}

export function formatSelection(
  value: string,
  selectionStart: number,
  selectionEnd: number,
  action: MarkdownAction,
): SelectionEdit {
  const selected = value.slice(selectionStart, selectionEnd)
  if (action.type === 'block') {
    const next = value.slice(0, selectionStart) + action.text + value.slice(selectionEnd)
    const cursor = selectionStart + action.text.length
    return { value: next, selectionStart: cursor, selectionEnd: cursor }
  }
  if (action.type === 'line-prefix') {
    const lineStart = value.lastIndexOf('\n', selectionStart - 1) + 1
    const next = value.slice(0, lineStart) + action.prefix + selected + value.slice(selectionEnd)
    return {
      value: next,
      selectionStart: lineStart + action.prefix.length,
      selectionEnd: lineStart + action.prefix.length + selected.length,
    }
  }

  const text = selected || action.sample
  const inserted = `${action.before}${text}${action.after}`
  return {
    value: value.slice(0, selectionStart) + inserted + value.slice(selectionEnd),
    selectionStart: selectionStart + action.before.length,
    selectionEnd: selectionStart + action.before.length + text.length,
  }
}

interface ToolbarItem {
  label: string
  title: string
  action: MarkdownAction | { type: 'link' } | { type: 'image' }
}

const TOOLBAR_ACTIONS: ToolbarItem[] = [
  { label: 'B', title: 'Fett (Strg+B)', action: { type: 'wrap', before: '**', after: '**', sample: 'Fettschrift' } },
  { label: 'I', title: 'Kursiv (Strg+I)', action: { type: 'wrap', before: '*', after: '*', sample: 'Kursiv' } },
  { label: '~~', title: 'Durchgestrichen', action: { type: 'wrap', before: '~~', after: '~~', sample: 'Text' } },
  { label: '—', title: 'Trenner', action: { type: 'block', text: '\n\n---\n\n' } },
  { label: '</>', title: 'Inline-Code', action: { type: 'wrap', before: '`', after: '`', sample: 'code' } },
  { label: '⌨ Block', title: 'Code-Block', action: { type: 'block', text: '\n\n```\n\n```\n\n' } },
  { label: '❝', title: 'Zitat', action: { type: 'line-prefix', prefix: '> ' } },
  { label: '🔗', title: 'Link', action: { type: 'link' } },
  { label: '🖼', title: 'Bild', action: { type: 'image' } },
  { label: '• Liste', title: 'Ungeordnete Liste', action: { type: 'line-prefix', prefix: '- ' } },
  { label: '1. Liste', title: 'Geordnete Liste', action: { type: 'line-prefix', prefix: '1. ' } },
  { label: 'H2', title: 'Überschrift 2', action: { type: 'line-prefix', prefix: '## ' } },
  { label: 'H3', title: 'Überschrift 3', action: { type: 'line-prefix', prefix: '### ' } },
]

function setPreviewContent(container: HTMLElement, html: string): void {
  const parsed = new DOMParser().parseFromString(html, 'text/html')
  parsed.querySelectorAll('script, noscript, iframe, object, embed').forEach((node) => node.remove())
  for (const element of parsed.querySelectorAll<HTMLElement>('*')) {
    for (const attribute of [...element.attributes]) {
      if (/^on/i.test(attribute.name)) element.removeAttribute(attribute.name)
      if (['href', 'src', 'xlink:href'].includes(attribute.name.toLowerCase())
        && /^\s*javascript:/i.test(attribute.value)) {
        element.removeAttribute(attribute.name)
      }
    }
  }
  container.replaceChildren(...Array.from(parsed.body.childNodes, (node) => document.importNode(node, true)))
}

function showInputDialog(label: string, type: string, initial: string): Promise<string | null> {
  return new Promise((resolve) => {
    document.getElementById('ap-inline-dialog')?.remove()
    const dialog = document.createElement('dialog')
    dialog.id = 'ap-inline-dialog'
    dialog.setAttribute('aria-label', label)
    const heading = document.createElement('h2')
    heading.textContent = label
    const input = document.createElement('input')
    input.type = type
    input.value = initial
    input.autocomplete = 'off'
    input.setAttribute('aria-label', label)
    const actions = document.createElement('div')
    const confirm = document.createElement('button')
    confirm.type = 'button'
    confirm.className = 'ap-dlg-ok'
    confirm.textContent = 'OK'
    const cancel = document.createElement('button')
    cancel.type = 'button'
    cancel.className = 'ap-dlg-cancel'
    cancel.textContent = 'Abbrechen'
    actions.append(confirm, cancel)
    dialog.append(heading, input, actions)
    document.body.append(dialog)

    const close = (value: string | null): void => {
      dialog.close()
      dialog.remove()
      resolve(value)
    }
    confirm.addEventListener('click', () => close(input.value.trim()))
    cancel.addEventListener('click', () => close(null))
    dialog.addEventListener('cancel', (event) => {
      event.preventDefault()
      close(null)
    })
    dialog.showModal()
    input.focus()
    input.select()
  })
}

function insertLinkOrImage(
  textarea: HTMLTextAreaElement,
  action: 'link' | 'image',
): void {
  const start = textarea.selectionStart
  const end = textarea.selectionEnd
  const selected = textarea.value.slice(start, end)
  const original = textarea.value
  const label = action === 'link' ? 'Link-URL eingeben' : 'Bild-URL eingeben'
  void showInputDialog(label, 'url', action === 'link' ? 'https://' : '').then((url) => {
    if (!url) return
    const text = selected || (action === 'link' ? 'Linktext' : 'Beschreibung')
    const markup = action === 'link' ? `[${text}](${url})` : `![${text}](${url})`
    textarea.value = original.slice(0, start) + markup + original.slice(end)
    textarea.setSelectionRange(start + (action === 'link' ? 1 : 2), start + (action === 'link' ? 1 : 2) + text.length)
    textarea.focus()
    textarea.dispatchEvent(new Event('input', { bubbles: true }))
  })
}

function buildToolbar(wrap: HTMLElement, textarea: HTMLTextAreaElement): HTMLElement {
  const toolbar = document.createElement('div')
  toolbar.className = 'ap-editor-toolbar'
  toolbar.setAttribute('role', 'toolbar')
  toolbar.setAttribute('aria-label', 'Formatierungs-Toolbar')

  for (const item of TOOLBAR_ACTIONS) {
    const button = document.createElement('button')
    button.type = 'button'
    button.textContent = item.label
    button.title = item.title
    button.setAttribute('aria-label', item.title)
    button.addEventListener('click', () => {
      if (item.action.type === 'link' || item.action.type === 'image') {
        insertLinkOrImage(textarea, item.action.type)
      } else {
        const edit = formatSelection(
          textarea.value,
          textarea.selectionStart,
          textarea.selectionEnd,
          item.action,
        )
        textarea.value = edit.value
        textarea.setSelectionRange(edit.selectionStart, edit.selectionEnd)
        textarea.dispatchEvent(new Event('input', { bubbles: true }))
        textarea.focus()
      }
    })
    toolbar.append(button)
  }

  const separator = document.createElement('span')
  separator.className = 'ap-toolbar-sep'
  separator.setAttribute('aria-hidden', 'true')
  toolbar.append(separator)
  const viewGroup = document.createElement('span')
  viewGroup.className = 'ap-toolbar-view-group'
  viewGroup.setAttribute('aria-label', 'Vorsicht-Modus')
  const views = [
    { id: 'edit', label: '✏ Nur Editor', title: 'Nur Eingabe anzeigen' },
    { id: 'split', label: '⬛⬜ Split', title: 'Editor und Vorschau nebeneinander' },
    { id: 'preview', label: '👁 Nur Preview', title: 'Nur Vorschau anzeigen' },
  ]
  for (const view of views) {
    const button = document.createElement('button')
    button.type = 'button'
    button.textContent = view.label
    button.title = view.title
    button.setAttribute('aria-label', view.title)
    button.setAttribute('aria-pressed', String(view.id === 'split'))
    if (view.id === 'split') button.classList.add('active')
    button.addEventListener('click', () => {
      wrap.querySelector('.ap-editor-split')?.classList.remove('ap-view-edit', 'ap-view-preview')
      if (view.id !== 'split') wrap.querySelector('.ap-editor-split')?.classList.add(`ap-view-${view.id}`)
      for (const sibling of viewGroup.querySelectorAll('button')) {
        sibling.classList.toggle('active', sibling === button)
        sibling.setAttribute('aria-pressed', String(sibling === button))
      }
    })
    viewGroup.append(button)
  }
  toolbar.append(viewGroup)
  return toolbar
}

export function mountBuiltinEditor(wrap: HTMLElement): void {
  const textarea = wrap.querySelector<HTMLTextAreaElement>('textarea[name="body"]')
  if (!textarea || wrap.dataset.editorMounted === 'true') return
  wrap.dataset.editorMounted = 'true'

  const toolbar = buildToolbar(wrap, textarea)
  wrap.prepend(toolbar)
  const split = document.createElement('div')
  split.className = 'ap-editor-split ap-view-split'
  const editorPane = document.createElement('div')
  editorPane.className = 'ap-editor-pane'
  const previewPane = document.createElement('section')
  previewPane.className = 'ap-preview-pane'
  previewPane.setAttribute('aria-label', 'Servergerenderte Markdown-Vorschau')
  const previewLabel = document.createElement('h3')
  previewLabel.className = 'ap-preview-label'
  previewLabel.textContent = 'Vorschau'
  const preview = document.createElement('div')
  preview.className = 'ap-preview-content ap-prose'
  preview.setAttribute('aria-live', 'polite')
  previewPane.append(previewLabel, preview)
  editorPane.append(textarea)
  split.append(editorPane, previewPane)
  wrap.append(split)

  const endpoint = wrap.dataset.apPreviewEndpoint
  let timer = 0
  let activeController: AbortController | undefined
  const renderPreview = async (): Promise<void> => {
    if (!endpoint) return
    activeController?.abort()
    activeController = new AbortController()
    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
        body: JSON.stringify({ text: textarea.value }),
        signal: activeController.signal,
      })
      if (!response.ok) throw new Error('Preview request failed')
      const data: unknown = await response.json()
      if (typeof data !== 'object' || data === null || !('html' in data) || typeof data.html !== 'string') {
        throw new Error('Invalid preview response')
      }
      setPreviewContent(preview, data.html)
    } catch (error: unknown) {
      if (error instanceof DOMException && error.name === 'AbortError') return
      preview.textContent = 'Vorschau nicht verfügbar. Der Markdown-Text bleibt unverändert.'
    }
  }

  textarea.addEventListener('input', () => {
    window.clearTimeout(timer)
    timer = window.setTimeout(() => void renderPreview(), Number(wrap.dataset.apDebounce) || 350)
  })
  textarea.addEventListener('keydown', (event) => {
    if (!(event.ctrlKey || event.metaKey)) return
    const key = event.key.toLowerCase()
    const item = key === 'b' ? TOOLBAR_ACTIONS[0] : key === 'i' ? TOOLBAR_ACTIONS[1] : undefined
    if (!item || item.action.type === 'link' || item.action.type === 'image') return
    event.preventDefault()
    const edit = formatSelection(textarea.value, textarea.selectionStart, textarea.selectionEnd, item.action)
    textarea.value = edit.value
    textarea.setSelectionRange(edit.selectionStart, edit.selectionEnd)
    textarea.dispatchEvent(new Event('input', { bubbles: true }))
  })
  void renderPreview()
}
