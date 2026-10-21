/* Minimal push-only worker: deliberately does not cache application content. */
self.addEventListener('push', (event) => {
  let payload = {}
  try { payload = event.data ? event.data.json() : {} } catch { payload = {} }
  const title = typeof payload.title === 'string' ? payload.title.slice(0, 120) : 'ArborPress'
  const body = typeof payload.body === 'string' ? payload.body.slice(0, 240) : 'Du hast eine neue Benachrichtigung.'
  const candidate = typeof payload.path === 'string' ? payload.path : '/notifications'
  const parsed = new URL(candidate, self.location.origin)
  const path = parsed.origin === self.location.origin ? `${parsed.pathname}${parsed.search}${parsed.hash}` : '/notifications'
  event.waitUntil(self.registration.showNotification(title, { body, data: { path } }))
})

self.addEventListener('notificationclick', (event) => {
  event.notification.close()
  const path = event.notification.data && typeof event.notification.data.path === 'string' ? event.notification.data.path : '/notifications'
  const candidate = new URL(path, self.location.origin)
  const destination = candidate.origin === self.location.origin ? candidate : new URL('/notifications', self.location.origin)
  event.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clients) => {
    const existing = clients.find((client) => new URL(client.url).origin === self.location.origin)
    if (existing && 'focus' in existing) {
      return existing.navigate(destination.href).then(() => existing.focus())
    }
    return self.clients.openWindow(destination.href)
  }))
})
