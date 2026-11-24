// Phone / browser push notifications (web push). Registers the service worker,
// asks permission, subscribes with the server's VAPID key, and hands the
// subscription to the backend so Live AI can notify this device even when the
// dashboard is closed.
import { api } from './api'

// VAPID public key arrives base64url; the browser needs it as a Uint8Array
function urlB64ToUint8Array(base64) {
    const pad = '='.repeat((4 - (base64.length % 4)) % 4)
    const b64 = (base64 + pad).replace(/-/g, '+').replace(/_/g, '/')
    const raw = atob(b64)
    const out = new Uint8Array(raw.length)
    for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i)
    return out
}

export function pushSupported() {
    return 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window
}

export async function registerSW() {
    if (!('serviceWorker' in navigator)) return null
    try { return await navigator.serviceWorker.register('/sw.js') } catch { return null }
}

// 'unsupported' | 'denied' | 'on' | 'off'
export async function currentPushState() {
    if (!pushSupported()) return 'unsupported'
    if (Notification.permission === 'denied') return 'denied'
    try {
        const reg = await navigator.serviceWorker.getRegistration()
        const sub = reg && await reg.pushManager.getSubscription()
        return sub ? 'on' : 'off'
    } catch { return 'off' }
}

export async function enablePush() {
    if (!pushSupported()) throw new Error('This browser does not support push notifications.')
    const perm = await Notification.requestPermission()
    if (perm !== 'granted') throw new Error('Notifications were not allowed.')
    await registerSW()
    const reg = await navigator.serviceWorker.ready
    const { key } = await api('/push/pubkey').then(r => r.json())
    const sub = (await reg.pushManager.getSubscription()) || await reg.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlB64ToUint8Array(key),
    })
    const r = await api('/push/subscribe', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(sub),
    })
    if (!r.ok) throw new Error('Could not register this device for push.')
    return true
}

export async function disablePush() {
    try {
        const reg = await navigator.serviceWorker.getRegistration()
        const sub = reg && await reg.pushManager.getSubscription()
        if (sub) {
            try {
                await api('/push/unsubscribe', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ endpoint: sub.endpoint }),
                })
            } catch { /* best effort */ }
            await sub.unsubscribe()
        }
    } catch { /* ignore */ }
    return true
}

// send a test push to all this account's registered devices
export async function sendTestPush() {
    const r = await api('/push/test', { method: 'POST' })
    if (!r.ok) throw new Error('Test push failed.')
    return r.json()
}
