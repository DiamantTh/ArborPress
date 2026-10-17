import assert from 'node:assert/strict'
import test from 'node:test'
import { base64URLStringToBuffer, bufferToBase64URLString } from '@simplewebauthn/browser'

import { getResponseError, parseAuthenticationOptions, parseRegistrationOptions } from '../src/lib/webauthn.ts'

test('validates challenge and per-user credential identifiers', () => {
  const options = parseAuthenticationOptions({
    challenge: 'AQID',
    userVerification: 'required',
    allowCredentials: [{ id: '-_8', type: 'public-key' }],
  })

  assert.deepEqual([...new Uint8Array(base64URLStringToBuffer(options.challenge))], [1, 2, 3])
  assert.deepEqual(
    [...new Uint8Array(base64URLStringToBuffer(options.allowCredentials?.[0].id ?? ''))],
    [251, 255],
  )
})

test('rejects malformed challenges, credential IDs, and weaker verification', () => {
  assert.throws(
    () => parseAuthenticationOptions({ challenge: '<script>', userVerification: 'required' }),
    /ungültige Challenge/,
  )
  assert.throws(
    () => parseAuthenticationOptions({ challenge: 'A', userVerification: 'required' }),
    /ungültige Challenge/,
  )
  assert.throws(
    () => parseAuthenticationOptions({
      challenge: 'AQID',
      userVerification: 'required',
      allowCredentials: [{ id: 'not/base64', type: 'public-key' }],
    }),
    /ungültige Credentials/,
  )
  assert.throws(
    () => parseAuthenticationOptions({ challenge: 'AQID', userVerification: 'preferred' }),
    /Benutzerverifikation/,
  )
})

test('validates registration identity, UV and excluded credentials', () => {
  const options = parseRegistrationOptions({
    challenge: 'AQID',
    rp: { name: 'ArborPress', id: 'localhost' },
    user: { id: 'BAUG', name: 'operator', displayName: 'Operator' },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    authenticatorSelection: { userVerification: 'required' },
    excludeCredentials: [{ id: 'BwgJ', type: 'public-key' }],
  })
  assert.equal(options.user.name, 'operator')
  assert.equal(options.authenticatorSelection?.userVerification, 'required')
  assert.throws(
    () => parseRegistrationOptions({
      challenge: 'AQID',
      user: { id: 'BAUG', name: 'operator', displayName: 'Operator' },
      authenticatorSelection: { userVerification: 'preferred' },
    }),
    /Benutzerverifikation/,
  )
  assert.throws(
    () => parseRegistrationOptions({
      challenge: 'AQID',
      user: { id: 'BAUG', name: 'operator', displayName: 'Operator' },
      authenticatorSelection: { userVerification: 'required' },
      excludeCredentials: [{ id: 'bad/id', type: 'public-key' }],
    }),
    /Credentials/,
  )
})

test('base64url credential encoding round-trips without padding', () => {
  const encoded = bufferToBase64URLString(Uint8Array.from([251, 255]).buffer)
  assert.equal(encoded, '-_8')
  assert.deepEqual([...new Uint8Array(base64URLStringToBuffer(encoded))], [251, 255])
})

test('uses structured server errors and hides non-JSON response bodies', async () => {
  const apiError = await getResponseError(
    new Response(JSON.stringify({ description: 'Anmeldung fehlgeschlagen.' }), {
      status: 401,
      headers: { 'content-type': 'application/json' },
    }),
    'Fallback',
  )
  assert.equal(apiError.message, 'Anmeldung fehlgeschlagen.')

  const htmlError = await getResponseError(
    new Response('<html>private internal traceback</html>', {
      status: 500,
      headers: { 'content-type': 'text/html' },
    }),
    'Anmeldung fehlgeschlagen.',
  )
  assert.equal(htmlError.message, 'Anmeldung fehlgeschlagen.')
})
