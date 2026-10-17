import assert from 'node:assert/strict'
import test from 'node:test'

import { formatSelection } from '../src/lib/editor/builtin.ts'
import { resolveEditorMode } from '../src/lib/editor/config.ts'

test('supports only statically bundled editor implementations', () => {
  assert.equal(resolveEditorMode('builtin'), 'builtin')
  assert.equal(resolveEditorMode('tiptap'), 'tiptap')
  assert.equal(resolveEditorMode('easymde'), 'fallback')
  assert.equal(resolveEditorMode('../remote-script'), 'fallback')
  assert.equal(resolveEditorMode(undefined), 'fallback')
})

test('formats a selected Markdown range without losing surrounding content', () => {
  assert.deepEqual(formatSelection('before text after', 7, 11, {
    type: 'wrap', before: '**', after: '**', sample: 'word',
  }), {
    value: 'before **text** after',
    selectionStart: 9,
    selectionEnd: 13,
  })
})

test('inserts a Markdown sample when there is no selection', () => {
  assert.deepEqual(formatSelection('start end', 6, 6, {
    type: 'wrap', before: '*', after: '*', sample: 'Kursiv',
  }), {
    value: 'start *Kursiv*end',
    selectionStart: 7,
    selectionEnd: 13,
  })
})
