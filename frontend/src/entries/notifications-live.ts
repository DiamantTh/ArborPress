export {}

import { notificationSocketAuth, reconnectDelay } from '../lib/notifications'

const root = document.querySelector<HTMLElement>('[data-notifications-live]')

if (root) {
  const ticketUrl = root.dataset.ticketUrl ?? ''
  const wsUrl = root.dataset.wsUrl ?? ''
  const csrf = root.dataset.csrf ?? ''
  const list = document.getElementById('notification-list')
  const count = document.getElementById('notification-unread-count')
  let stopped = false
  let attempts = 0

  const setCount = (value: number): void => {
    if (count) count.textContent = String(Math.max(0, value))
  }

  const addNotification = (item: Record<string, unknown>): void => {
    const id = String(item.id ?? '')
    if (!list || !id || list.querySelector(`[data-notification-id="${CSS.escape(id)}"]`)) return
    const li = document.createElement('li')
    li.dataset.notificationId = id
    li.className = 'is-unread'
    const title = document.createElement('h2')
    title.textContent = String(item.title ?? 'Neue Benachrichtigung')
    const message = document.createElement('p')
    message.textContent = String(item.message ?? '')
    li.append(title, message)
    const target = item.target_path
    if (typeof target === 'string' && target.startsWith('/') && !target.startsWith('//')) {
      const link = document.createElement('a')
      link.href = target
      link.textContent = 'Öffnen'
      li.append(link)
    }
    list.prepend(li)
  }

  const connect = async (): Promise<void> => {
    if (stopped || !ticketUrl || !wsUrl) return
    try {
      const ticketResponse = await fetch(ticketUrl, {
        method: 'POST', credentials: 'same-origin',
        headers: { 'X-CSRF-Token': csrf },
      })
      if (ticketResponse.status === 401 || ticketResponse.status === 403) {
        stopped = true
        return
      }
      if (!ticketResponse.ok) throw new Error('Ticket unavailable')
      const ticket = await ticketResponse.json() as { ticket: string; protocol: string }
      const socket = new WebSocket(wsUrl)
      socket.addEventListener('open', () => {
        socket.send(notificationSocketAuth(
          ticket.protocol,
          ticket.ticket,
          sessionStorage.getItem('ap-notification-cursor'),
        ))
      }, { once: true })
      socket.addEventListener('message', (event) => {
        if (typeof event.data !== 'string' || event.data.length > 16_384) {
          socket.close()
          return
        }
        try {
          const message = JSON.parse(event.data) as Record<string, unknown>
          if (message.type === 'unread_count' && typeof message.count === 'number') setCount(message.count)
          if (message.type === 'notification' && message.notification && typeof message.notification === 'object') {
            const item = message.notification as Record<string, unknown>
            addNotification(item)
            if (typeof item.id === 'string') sessionStorage.setItem('ap-notification-cursor', item.id)
          }
          if (message.type === 'ready') attempts = 0
        } catch { socket.close() }
      })
      socket.addEventListener('close', () => {
        if (stopped) return
        attempts += 1
        window.setTimeout(() => void connect(), reconnectDelay(attempts))
      }, { once: true })
    } catch {
      attempts += 1
      window.setTimeout(() => void connect(), reconnectDelay(attempts))
    }
  }
  void connect()
}
