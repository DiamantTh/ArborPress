import '../styles/editor.css'
import { mountBuiltinEditor } from '../lib/editor/builtin.js'
import { resolveEditorMode } from '../lib/editor/config.js'

for (const wrap of document.querySelectorAll<HTMLElement>('[data-ap-editor]')) {
  if (resolveEditorMode(wrap.dataset.apEditor) === 'builtin') mountBuiltinEditor(wrap)
}
