import helpers from './helpers.js'

const b64 = helpers.uint8ArrayToBase64Url

/**
 * @param {{ publicKey: Uint8Array; privateKey: Uint8Array; }} vapidKeys
 * @param {string} audience
 * @param {string} subject
 * @param {number} [exp]
 */
export default async function createVapidAuthHeader(
  vapidKeys, audience, subject, exp
) {
  if (!audience) {
    throw new Error('Audience must be the origin of the server')
  }

  if (!subject) {
    throw new Error('Subject must be either a mailto or http link')
  }

  if (typeof exp !== 'number') {
    // The `exp` field will contain the current
    // timestamp in UTC plus twelve hours.
    exp = Math.floor((Date.now() / 1000) + 43200)
  }

  // Ensure the audience is just the origin
  audience = new URL(audience).origin

  const tokenHeader = {
    typ: 'JWT',
    alg: 'ES256',
  }

  const tokenBody = {
    aud: audience,
    exp: exp,
    sub: subject,
  }

  // Utility function for UTF-8 encoding a string to an ArrayBuffer.
  const utf8Encoder = new TextEncoder()

  // The unsigned token is the concatenation of the URL-safe base64 encoded
  // header and body.
  const unsignedToken =
    b64(utf8Encoder.encode(JSON.stringify(tokenHeader))) + '.' +
    b64(utf8Encoder.encode(JSON.stringify(tokenBody)))

  // Sign the |unsignedToken| using ES256 (SHA-256 over ECDSA).
  const keyData = {
    kty: 'EC',
    crv: 'P-256',
    x: b64(vapidKeys.publicKey.subarray(1, 33)),
    y: b64(vapidKeys.publicKey.subarray(33, 65)),
    d: b64(vapidKeys.privateKey)
  }

  // Sign the |unsignedToken| with the server's private key to generate
  // the signature.
  const key = await crypto.subtle.importKey('jwk', keyData, {
    name: 'ECDSA', namedCurve: 'P-256',
  }, true, ['sign'])
  const signature = await crypto.subtle.sign({
    name: 'ECDSA',
    hash: { name: 'SHA-256' },
  }, key, utf8Encoder.encode(unsignedToken))
  const jsonWebToken = unsignedToken + '.' + b64(new Uint8Array(signature))
  const p256ecdsa = b64(vapidKeys.publicKey)

  return {
    'Authorization': `WebPush ${jsonWebToken}`,
    'Crypto-Key': `p256ecdsa=${p256ecdsa}`
  }
}
