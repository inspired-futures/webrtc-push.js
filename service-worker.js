/// <reference lib="es2020" />
/// <reference lib="webworker" />

/**
 * @type {ServiceWorkerGlobalScope}
 */// @ts-ignore
const sw = globalThis

sw.addEventListener('install', () => {
  sw.skipWaiting()
})

sw.addEventListener('activate', event => {
  event.waitUntil(sw.clients.claim())
})

sw.addEventListener('push', async evt => {
  // Read the push message that was sent
  const payload = evt.data?.json()

  // Broadcast the message to all tabs
  sw.clients.matchAll().then(clients => {
    clients.forEach(client => client.postMessage(payload))
  })
})

sw.addEventListener('message', evt => {
  if (evt.data === 'claimMe') {
    sw.clients.claim()
  }
})
