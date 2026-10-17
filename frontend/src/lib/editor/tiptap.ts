import { Editor } from '@tiptap/core'
import StarterKit from '@tiptap/starter-kit'
import { Markdown, type MarkdownStorage } from 'tiptap-markdown'

interface MarkdownEditorStorage {
  markdown: MarkdownStorage
}

function markdownStorage(editor: Editor): MarkdownStorage {
  return (editor.storage as unknown as MarkdownEditorStorage).markdown
}

export function mountTiptapEditor(wrap: HTMLElement): void {
  const textarea = wrap.querySelector<HTMLTextAreaElement>('textarea[name="body"]')
  if (!textarea || wrap.dataset.editorMounted === 'true') return

  const initialMarkdown = textarea.value
  const container = document.createElement('section')
  container.className = 'ap-tiptap'
  const toolbar = document.createElement('div')
  toolbar.className = 'ap-tiptap__toolbar'
  toolbar.setAttribute('role', 'toolbar')
  toolbar.setAttribute('aria-label', 'Editor-Werkzeuge')
  const content = document.createElement('div')
  content.className = 'ap-tiptap__content'
  content.setAttribute('aria-label', 'Formatierter Inhalt')
  const raw = document.createElement('textarea')
  raw.className = 'ap-tiptap__raw code-editor'
  raw.setAttribute('aria-label', 'Markdown-Quelltext')
  raw.hidden = true
  container.append(toolbar, content, raw)
  textarea.insertAdjacentElement('beforebegin', container)

  let editor: Editor
  try {
    editor = new Editor({
      element: content,
      extensions: [
        StarterKit,
        Markdown.configure({
          html: false,
          tightLists: true,
          transformPastedText: true,
          transformCopiedText: false,
        }),
      ],
      content: initialMarkdown,
      autofocus: false,
    })
  } catch (error: unknown) {
    container.remove()
    throw error
  }

  const makeButton = (label: string, title: string, action: () => void): HTMLButtonElement => {
    const button = document.createElement('button')
    button.type = 'button'
    button.textContent = label
    button.title = title
    button.setAttribute('aria-label', title)
    button.addEventListener('click', (event) => {
      event.preventDefault()
      action()
    })
    toolbar.append(button)
    return button
  }

  makeButton('B', 'Fett', () => editor.chain().focus().toggleBold().run())
  makeButton('I', 'Kursiv', () => editor.chain().focus().toggleItalic().run())
  makeButton('~~', 'Durchgestrichen', () => editor.chain().focus().toggleStrike().run())
  makeButton('`', 'Code', () => editor.chain().focus().toggleCode().run())
  makeButton('H1', 'Überschrift 1', () => editor.chain().focus().toggleHeading({ level: 1 }).run())
  makeButton('H2', 'Überschrift 2', () => editor.chain().focus().toggleHeading({ level: 2 }).run())
  makeButton('H3', 'Überschrift 3', () => editor.chain().focus().toggleHeading({ level: 3 }).run())
  makeButton('UL', 'Liste (Punkte)', () => editor.chain().focus().toggleBulletList().run())
  makeButton('OL', 'Liste (Nummern)', () => editor.chain().focus().toggleOrderedList().run())
  makeButton('```', 'Code-Block', () => editor.chain().focus().toggleCodeBlock().run())
  makeButton('—', 'Trennlinie', () => editor.chain().focus().setHorizontalRule().run())

  const separator = document.createElement('span')
  separator.className = 'ap-tiptap__separator'
  separator.setAttribute('role', 'separator')
  separator.setAttribute('aria-orientation', 'vertical')
  toolbar.append(separator)

  let rawMode = false
  const markdownToggle = makeButton('MD ⇄', 'Markdown-Quelltextmodus umschalten', () => {
    rawMode = !rawMode
    markdownToggle.setAttribute('aria-pressed', String(rawMode))
    if (rawMode) {
      raw.value = markdownStorage(editor).getMarkdown()
      content.hidden = true
      raw.hidden = false
      raw.focus()
    } else {
      editor.commands.setContent(raw.value, { emitUpdate: false })
      raw.hidden = true
      content.hidden = false
      editor.commands.focus()
    }
  })
  markdownToggle.setAttribute('aria-pressed', 'false')

  const syncTextarea = (): void => {
    textarea.value = rawMode ? raw.value : markdownStorage(editor).getMarkdown()
  }
  const form = wrap.closest('form')
  form?.addEventListener('submit', syncTextarea)
  editor.on('update', syncTextarea)

  textarea.hidden = true
  textarea.setAttribute('aria-hidden', 'true')
  wrap.dataset.editorMounted = 'true'
}
