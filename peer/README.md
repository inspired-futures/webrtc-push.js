How is it "perfect"?
This is how: https://blog.mozilla.org/webrtc/perfect-negotiation-in-webrtc

- This p2p uses a so called "polite" peer that rollsback on collision.<br>
  Should read the article to understand more.

- This p2p also adds a pre negotiated DataChannel with a predfined id to
  reduce sdp offer/answer. so it don't have to deal with on ondatachannel events 
  This channel is also used for further negotiation so that a signaling
  server isn't needed anymore
  
- This p2p add option to disable trickle so it can reduce the amount of
  roundtrip it needs to establish a p2p connection for the cost of
  slightly longer time it might take.<br>
  This gets set to true when a connection have been establish for faster
  futer negotiation needed events


unlike simple-peer this dose not have node specific stuff like Node streams,
buffer or EventEmitter. So in a since this is more plain lightweight

You might have to do more manual work but somethimes it's worth the effort to
reduce all un-needed bloated code that you don't use

```js
import Peer from 'https://jimmy.warting.se/packages/webrtc/perfect-negotiation.js'

const peer = Peer({ 
  polite: true, // the peer that says you go ahead I will rollback on colision
  trickle: true, // default
  signal // AbortSignal to stop all event listener and disconnect the peer
})

// only used to signal description and candidates to the other peer
// once a connection is establish the DataChannel takes over.
peer.signalingPort.onmessage = ({data}) => {
  // send data to the other peer somehow
}

io.on('recive-signal', data => {
  peer.signalingPort.postMessage(data)
})

/**
 * RTCPeerConnection
 */
peer.pc 

/** 
 * RTCDataChannel - You could use this channel  to send messages but it's
 * recommended that you create your own channel as this gets used for 
 * further negotiation events so it has it own logic
 *   peer.pc.createDataChannel(...)
 */
peer.dc.onopen = () => {
  peer.dc.send('Hi, Nice to talk to you')
}
```
