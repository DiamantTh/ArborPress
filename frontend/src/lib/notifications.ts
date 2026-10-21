export function decodeVapidKey(value: string): ArrayBuffer {
  const padded = value + '='.repeat((4 - value.length % 4) % 4)
  const binary = atob(padded.replace(/-/g, '+').replace(/_/g, '/'))
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0))
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer
}

export function notificationSocketAuth(
  protocol: string,
  ticket: string,
  lastSeen: string | null,
): string {
  return JSON.stringify({ protocol, ticket, last_seen_notification_id: lastSeen })
}

export function reconnectDelay(attempt: number, randomValue = Math.random()): number {
  const base = Math.min(30_000, 1000 * 2 ** Math.min(Math.max(attempt, 0), 5))
  return Math.min(
    30_000,
    Math.round(base * (0.75 + Math.min(1, Math.max(0, randomValue)) * 0.5)),
  )
}

export function sameOriginTarget(value: unknown, origin: string): string {
  if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//')) {
    return '/notifications'
  }
  try {
    const url = new URL(value, origin)
    return url.origin === origin ? `${url.pathname}${url.search}${url.hash}` : '/notifications'
  } catch {
    return '/notifications'
  }
}
