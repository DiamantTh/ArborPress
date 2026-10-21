import assert from 'node:assert/strict'
import test from 'node:test'

import {
  decodeVapidKey,
  notificationSocketAuth,
  reconnectDelay,
  sameOriginTarget,
} from '../src/lib/notifications.ts'

test('WSS authentication is a first-frame payload and retains the cursor', () => {
  assert.deepEqual(
    JSON.parse(notificationSocketAuth('arborpress.notifications.v1', 'ticket-value', 'n-1')),
    {
      protocol: 'arborpress.notifications.v1',
      ticket: 'ticket-value',
      last_seen_notification_id: 'n-1',
    },
  )
})

test('reconnect delay is jittered and bounded', () => {
  assert.equal(reconnectDelay(0, 0), 750)
  assert.equal(reconnectDelay(50, 1), 30_000)
})

test('notification navigation remains on the ArborPress origin', () => {
  assert.equal(sameOriginTarget('/posts/example?x=1', 'https://blog.example.test'), '/posts/example?x=1')
  assert.equal(sameOriginTarget('//attacker.test/path', 'https://blog.example.test'), '/notifications')
  assert.equal(sameOriginTarget('/\\attacker.test/path', 'https://blog.example.test'), '/notifications')
  assert.equal(sameOriginTarget('javascript:alert(1)', 'https://blog.example.test'), '/notifications')
})

test('VAPID URL-safe key is decoded as a dedicated buffer', () => {
  assert.deepEqual(Array.from(new Uint8Array(decodeVapidKey('AQIDBA'))), [1, 2, 3, 4])
})
