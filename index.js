// There is some slight diviation from the tutorial in the blog post
// I use a different sendPushMessage function and i also lazy load the push encryption lib

import Peer from './peer/perfect-negotiation.js'

const APPLICATION_KEYS = {
  privateKey: '8p1V7-l8NH-8Li1Ry6T5ddBxIq6zMjC0Nlr6_ATIsRg',
  publicKey: 'BHcoc0c11dFJnVcUDHhzp76eSuf8y4vqM0RYr_l5NnPC835_eiHpjEDhKwvZa4-vSEv0TzM5ozfv3BZ4LNCdyZ8'
}

// we can create a WebRTC peer early so it have some time
// to gather ice candidates
const peer = new Peer({
  // We want to send as few push messages as needed
  // since push messages is costly and have a quota
  // on how many push messages you can send
  // (specially when sending silent push)
  trickle: false,

  // Both are going to start out as polite but first person to
  // receive a push message isn't going to be polite
  polite: true
})

// Install the service worker
navigator.serviceWorker.register('./service-worker.js')

// Listen for when a service worker is broadcasting a push event
navigator.serviceWorker.addEventListener('message', async evt => {
  const payload = evt.data
  const { subscription: caller, ...sdp } = payload

  console.info('Received a push payload', payload)
  callButton.disabled = true
  // The first signal (push) message is going to have push subscription
  // from the sender that we (the receiver) can use when sending back messages
  if (caller) {
    peer.polite = false
    // Start listening for offer/answer signals
    peer.signalingPort.onmessage = ({ data }) => {
      sendPushMessage(caller, data)
    }
  }

  // Send the remaining sdp signal to the peer
  peer.signalingPort.postMessage(JSON.stringify(sdp))
})



/** @type {HTMLButtonElement} */
const callButton = document.querySelector('#callButton')
callButton.onclick = async () => {
  callButton.disabled = true
  if (Notification.permission !== 'granted') {
    await Notification.requestPermission()
  }

  const friendsSubscription = prompt(
    'Who would you like to call? enters someones Push Subscription',
    sessionStorage.lastSubscription
  )

  sessionStorage.lastSubscription = friendsSubscription

  // We are going to need our own subscription also
  // So we can tell our friend who is calling him and reply back
  let registration = await navigator.serviceWorker.ready
  let subscription =
    await registration.pushManager.getSubscription() ||
    await registration.pushManager.subscribe({
      userVisibleOnly: true, // a chrome requirement...
      applicationServerKey: APPLICATION_KEYS.publicKey
    })

  // Now that we have two subscription we can begin talking to each other
  peer.signalingPort.onmessage = ({ data }) => {
    // Embed our own push subscription into the first signal message
    // so that he or she can respond back
    data = ({ subscription, ...JSON.parse(data) })

    // Now send it via web push
    sendPushMessage(
      JSON.parse(friendsSubscription),
      JSON.stringify(data)
    )

    // It could be useful to always send my own subscription.
    // or some other form of identification as long the receiver
    // have a id<->subscription mapping but for the sake of simplicity
    // we will only deal with one p2p connection at the time
    // + a subscription can be quite lengthy and a push payload is fairly
    // limited i guess. but i don't think the size is an issue.
    subscription = undefined
  }
}

let encryptionHelper

async function sendPushMessage (subscription, text) {
  const uint8 = new TextEncoder().encode(text)
  if (!encryptionHelper) {
    const { default: EncryptionHelperAES128GCM } =
      await import('./webpush/encryption-aes128gcm.js')

    encryptionHelper = new EncryptionHelperAES128GCM({
      vapidKeys: APPLICATION_KEYS,
      // contact information for push service to contact you
      // in case of problem. It's either a mailto: or https: link
      subject: 'https://jimmy.warting.se'
    })
  }

  // Return an array that can be passed to fetch as arguments
  const request = await encryptionHelper.getRequestDetails(
    subscription,
    uint8
  )

  console.info('sending push message', JSON.parse(text))
  // Cors support on a push services is a reasonable SHOULD requirement
  // https://github.com/w3c/push-api/issues/303

  // Currently only mozilla have CORS enabled.
  // So we can make request directly to them.
  if (request[0].includes('mozilla.com')) {
    return fetch(...request)
  }

  // As for the rest: poke the bear and tell them to enable CORS support
  // In the meanwhile we will have to use a CORS proxy - you should really build
  // your own proxy and not relay on anyone elses
  return sendRequestToProxyServer(...request)
}

async function sendRequestToProxyServer(url, requestInfo) {
  console.debug("sendRequestToProxyServer", url, requestInfo);
  return fetch('https://corsproxy.io/?' + encodeURIComponent(url), requestInfo)
}









/* ---------------------------------------
The rest of the script is just for Demo
and will most likely be unrelevent for you
--------------------------------------- */
var orig = console.info
console.info = (m, ...rest) => (orig(m, ...rest), (pre.innerText += '\n\n' + m))

/** @type {HTMLPreElement} */
const pre = document.querySelector('#yourSubscription')
navigator.serviceWorker.ready.then(async reg => {
  const sub = await reg.pushManager.getSubscription()
  if (sub) {
    showSubButton.remove()
    pre.innerText = 'Here is your own push subscription:\n'
                  + JSON.stringify(sub, null, 2)
  }
})

/** @type {HTMLButtonElement} */
const showSubButton = document.querySelector('#showMySubscription')
showSubButton.hidden = false
showSubButton.onclick = async () => {
  // We are going to need our own subscription also
  // So we can tell our friend who is calling him and reply back
  let registration = await navigator.serviceWorker.ready
  let subscription =
    await registration.pushManager.getSubscription() ||
    await registration.pushManager.subscribe({
      userVisibleOnly: true, // a chrome requirement...
      applicationServerKey: APPLICATION_KEYS.publicKey
    })
  showSubButton.remove()
  pre.innerText = 'Here is your own push subscription:\n' + JSON.stringify(subscription, null, 2)
}


peer.dc.onopen = () => {
  console.info('You are now connected with another peer')
  const btn = document.createElement('button')
  btn.innerText = 'Create a canvas clock, capture stream and add it to the peer'
  btn.onclick = whiteNoise
  callButton.after(btn)
}

peer.pc.ontrack = ({streams: [stream]}) => {
  console.info('The other peer gave us a stream')
  const video = document.createElement('video')
  pre.after(video)
  video.controls = true
  video.muted = true
  video.autoplay = true
  video.srcObject = stream
}

async function whiteNoise() {
  const { AnalogClock } = await import('./dummycontent/canvas-clock.js')
  const clock = new AnalogClock()
  const stream = clock.canvas.captureStream()
  pre.after(clock.canvas)
  peer.pc.addTransceiver(stream.getTracks()[0], { streams: [stream] })
}
