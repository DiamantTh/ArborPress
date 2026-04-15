/**
 * ArborPress TipTap Editor-Adapter
 *
 * Registriert sich als "tiptap" im ArborPressEditor-Registry.
 * Bietet WYSIWYG-Bearbeitung via TipTap/ProseMirror + einen
 * umschaltbaren Markdown-Quelltextmodus.
 *
 * Ausgabeformat: Markdown (body_md bleibt primäre Quelle).
 * _editor_type bleibt "markdown" → backend braucht keine HTML-Pfade.
 */

import { Editor } from '@tiptap/core'
import StarterKit from '@tiptap/starter-kit'
import { Markdown } from 'tiptap-markdown'

// Globaler Registry, bereitgestellt von editor-registry.js
declare global {
  interface Window {
    ArborPressEditor: {
      register(
        id: string,
        factory: (wrap: HTMLElement, opts: Record<string, unknown>) => AdapterInstance
      ): void
    }
  }
}

interface AdapterInstance {
  getValue(): string
  setValue(value: string): void
  focus(): void
  destroy(): void
}

window.ArborPressEditor.register('tiptap', (wrap: HTMLElement, _opts): AdapterInstance => {
  // ── DOM-Referenzen ───────────────────────────────────────────────────────
  const textarea = wrap.querySelector<HTMLTextAreaElement>('textarea[name="body"]')
  if (!textarea) throw new Error('[ap-tiptap] textarea[name="body"] nicht gefunden')
  const initialMd = textarea.value

  // Sichtbarkeit der Textarea ausblenden (Registry synct getValue() bei Submit)
  textarea.style.display = 'none'
  textarea.setAttribute('aria-hidden', 'true')

  // ── Äußerer Container ────────────────────────────────────────────────────
  const container = document.createElement('div')
  container.className = 'ap-tiptap'
  container.setAttribute('style', 'border:1px solid var(--admin-border,#ccc);border-radius:4px;overflow:hidden;')
  textarea.insertAdjacentElement('beforebegin', container)

  // ── Toolbar ──────────────────────────────────────────────────────────────
  const toolbar = document.createElement('div')
  toolbar.className = 'ap-tiptap__toolbar'
  toolbar.setAttribute('role', 'toolbar')
  toolbar.setAttribute('aria-label', 'Editor-Werkzeuge')
  toolbar.setAttribute('style', 'display:flex;gap:.25rem;padding:.35rem .5rem;background:var(--admin-bg-alt,#f5f5f5);border-bottom:1px solid var(--admin-border,#ccc);flex-wrap:wrap;')
  container.appendChild(toolbar)

  // Formatierungs-Buttons
  const btnDefs: Array<{ label: string; title: string; action: () => boolean }> = []

  // ── WYSIWYG-Inhaltsbereich ───────────────────────────────────────────────
  const editorEl = document.createElement('div')
  editorEl.className = 'ap-tiptap__content'
  editorEl.setAttribute('style', 'min-height:320px;padding:.75rem;background:var(--admin-bg,#fff);cursor:text;')
  container.appendChild(editorEl)

  // ── Markdown-Quelltextbereich ────────────────────────────────────────────
  const rawArea = document.createElement('textarea')
  rawArea.className = 'ap-tiptap__raw code-editor'
  rawArea.setAttribute('aria-label', 'Markdown-Quelltext')
  rawArea.setAttribute('style', 'display:none;width:100%;min-height:320px;padding:.75rem;box-sizing:border-box;border:none;font-family:monospace;resize:vertical;background:var(--admin-bg,#fff);')
  container.appendChild(rawArea)

  // ── TipTap-Instanz erstellen ─────────────────────────────────────────────
  const editor = new Editor({
    element: editorEl,
    extensions: [
      StarterKit.configure({
        // Code-Block: Monospace, kein Syntax-Highlight (kein CDN-Paket nötig)
        codeBlock: true,
      }),
      Markdown.configure({
        html: false,           // Kein rohes HTML in MD-Output – sicher
        tightLists: true,
        transformPastedText: true,
        transformCopiedText: false,
      }),
    ],
    content: '',
    autofocus: false,
  })

  // Initiale MD-Inhalte laden
  if (initialMd) {
    editor.commands.setMarkdownContent(initialMd, false)
  }

  // ── Toolbar-Buttons ──────────────────────────────────────────────────────
  const makeBtn = (
    label: string,
    title: string,
    action: () => void,
    getActive?: () => boolean
  ): HTMLButtonElement => {
    const btn = document.createElement('button')
    btn.type = 'button'
    btn.textContent = label
    btn.title = title
    btn.setAttribute('aria-label', title)
    btn.setAttribute('style', 'padding:.2rem .5rem;border:1px solid var(--admin-border,#ccc);background:var(--admin-bg,#fff);border-radius:3px;cursor:pointer;font-size:.85rem;')
    btn.addEventListener('click', (e) => {
      e.preventDefault()
      action()
    })
    toolbar.appendChild(btn)
    return btn
  }

  makeBtn('B', 'Fett',         () => editor.chain().focus().toggleBold().run())
  makeBtn('I', 'Kursiv',       () => editor.chain().focus().toggleItalic().run())
  makeBtn('~~', 'Durchgestrichen', () => editor.chain().focus().toggleStrike().run())
  makeBtn('`', 'Code',         () => editor.chain().focus().toggleCode().run())
  makeBtn('H1', 'Überschrift 1', () => editor.chain().focus().toggleHeading({ level: 1 }).run())
  makeBtn('H2', 'Überschrift 2', () => editor.chain().focus().toggleHeading({ level: 2 }).run())
  makeBtn('H3', 'Überschrift 3', () => editor.chain().focus().toggleHeading({ level: 3 }).run())
  makeBtn('UL', 'Liste (Punkte)',  () => editor.chain().focus().toggleBulletList().run())
  makeBtn('OL', 'Liste (Nummern)', () => editor.chain().focus().toggleOrderedList().run())
  makeBtn('```', 'Code-Block',  () => editor.chain().focus().toggleCodeBlock().run())
  makeBtn('—', 'Trennlinie',    () => editor.chain().focus().setHorizontalRule().run())

  // Trennstrich vor MD-Toggle
  const sep = document.createElement('span')
  sep.setAttribute('role', 'separator')
  sep.setAttribute('aria-orientation', 'vertical')
  sep.setAttribute('style', 'border-left:1px solid var(--admin-border,#ccc);margin:0 .25rem;')
  toolbar.appendChild(sep)

  // ── MD-Quelltextmodus-Toggle ─────────────────────────────────────────────
  let rawMode = false
  const mdToggleBtn = makeBtn('MD ⇄', 'Markdown-Quelltextmodus umschalten', () => {
    rawMode = !rawMode
    mdToggleBtn.setAttribute('aria-pressed', String(rawMode))
    mdToggleBtn.setAttribute('style', 
      rawMode
        ? 'padding:.2rem .5rem;border:1px solid var(--admin-accent,#333);background:var(--admin-accent,#333);color:#fff;border-radius:3px;cursor:pointer;font-size:.85rem;'
        : 'padding:.2rem .5rem;border:1px solid var(--admin-border,#ccc);background:var(--admin-bg,#fff);border-radius:3px;cursor:pointer;font-size:.85rem;'
    )
    if (rawMode) {
      // WYSIWYG → MD-Quelltext
      rawArea.value = editor.storage.markdown.getMarkdown()
      editorEl.style.display = 'none'
      rawArea.style.display = 'block'
      rawArea.focus()
    } else {
      // MD-Quelltext → WYSIWYG
      editor.commands.setMarkdownContent(rawArea.value, false)
      rawArea.style.display = 'none'
      editorEl.style.display = 'block'
      editor.commands.focus()
    }
  })
  mdToggleBtn.setAttribute('aria-pressed', 'false')

  // ── Adapter-API ──────────────────────────────────────────────────────────
  function getValue(): string {
    if (rawMode) {
      return rawArea.value
    }
    return editor.storage.markdown.getMarkdown()
  }

  function setValue(md: string): void {
    editor.commands.setMarkdownContent(md, false)
    if (rawMode) {
      rawArea.value = md
    }
  }

  function focus(): void {
    if (rawMode) {
      rawArea.focus()
    } else {
      editor.commands.focus()
    }
  }

  function destroy(): void {
    editor.destroy()
    container.remove()
    textarea.style.display = ''
    textarea.removeAttribute('aria-hidden')
  }

  return { getValue, setValue, focus, destroy }
})
