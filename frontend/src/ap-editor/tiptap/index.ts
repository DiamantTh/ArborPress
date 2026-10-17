import { mountTiptapEditor } from '../../lib/editor/tiptap.js'

for (const wrap of document.querySelectorAll<HTMLElement>('[data-ap-editor="tiptap"]')) {
  try {
    mountTiptapEditor(wrap)
  } catch {
    const message = document.createElement('p')
    message.className = 'flash flash--error'
    message.setAttribute('role', 'alert')
    message.textContent = 'Der Rich-Text-Editor konnte nicht geladen werden. Das Markdown-Textfeld bleibt verfügbar.'
    wrap.before(message)
  }
}
