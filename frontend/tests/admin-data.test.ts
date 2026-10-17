import assert from 'node:assert/strict'
import test from 'node:test'

import { parseCaptchaQuestions } from '../src/lib/admin-data.ts'

test('parses the server-rendered captcha question payload', () => {
  assert.deepEqual(parseCaptchaQuestions('[{"q":"Question?","a":"Answer"}]'), [
    { q: 'Question?', a: 'Answer' },
  ])
})

test('keeps an empty captcha question list empty for the component default', () => {
  assert.deepEqual(parseCaptchaQuestions('[]'), [])
})

test('rejects malformed captcha question payloads', () => {
  assert.throws(() => parseCaptchaQuestions('{'), SyntaxError)
  assert.throws(() => parseCaptchaQuestions('{"q":"Question?"}'), /array/)
  assert.throws(() => parseCaptchaQuestions('[{"q":1,"a":"Answer"}]'), /invalid shape/)
})
