export type EditorMode = 'builtin' | 'tiptap' | 'fallback'

/** Keep the browser registry static; unsupported legacy adapters stay a textarea. */
export function resolveEditorMode(value: string | undefined): EditorMode {
  if (value === 'builtin' || value === 'tiptap') return value
  return 'fallback'
}
