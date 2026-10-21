export {}

import { decodeVapidKey } from '../lib/notifications'

const button = document.querySelector<HTMLButtonElement>('[data-web-push-enable]')
const root = document.querySelector<HTMLElement>('[data-notifications-live]')

button?.addEventListener('click', async () => {
  const status = document.getElementById('notification-channel-status')
  const csrf = root?.dataset.csrf ?? ''
  try {
    if (!('serviceWorker' in navigator) || !('PushManager' in window) || !('Notification' in window)) {
      throw new Error('Web Push wird von diesem Browser nicht unterstützt.')
    }
    const permission = await Notification.requestPermission()
    if (permission !== 'granted') throw new Error('Browser-Benachrichtigungen wurden nicht freigegeben.')
    const response = await fetch('/notifications/web-push/key', { credentials: 'same-origin' })
    if (!response.ok) throw new Error('Push-Konfiguration ist nicht verfügbar.')
    const { publicKey } = await response.json() as { publicKey: string }
    if (!publicKey) throw new Error('Push ist auf dieser Instanz nicht konfiguriert.')
    const registration = await navigator.serviceWorker.register('/service-worker.js', { scope: '/' })
    const subscription = await registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: decodeVapidKey(publicKey),
    })
    const stored = await fetch('/notifications/web-push/subscribe', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
      body: JSON.stringify(subscription.toJSON()),
    })
    if (!stored.ok) throw new Error('Push-Abonnement konnte nicht gespeichert werden.')
    if (status) status.textContent = 'Web Push ist für diesen Browser aktiviert.'
  } catch (error) {
    if (status) status.textContent = error instanceof Error ? error.message : 'Push konnte nicht aktiviert werden.'
  }
})

document.querySelectorAll<HTMLButtonElement>('[data-web-push-remove]').forEach((removeButton) => {
  removeButton.addEventListener('click', async () => {
    const status = document.getElementById('notification-channel-status')
    const csrf = root?.dataset.csrf ?? ''
    try {
      const registration = await navigator.serviceWorker.getRegistration('/')
      const subscription = await registration?.pushManager.getSubscription()
      if (subscription) await subscription.unsubscribe()
      const response = await fetch('/notifications/web-push/unsubscribe', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
        body: JSON.stringify({ subscription_id: removeButton.dataset.webPushRemove }),
      })
      if (!response.ok) throw new Error('Abonnement konnte nicht entfernt werden.')
      removeButton.closest('li')?.remove()
      if (status) status.textContent = 'Browser-Abonnement entfernt.'
    } catch (error) {
      if (status) status.textContent = error instanceof Error ? error.message : 'Entfernen fehlgeschlagen.'
    }
  })
})
