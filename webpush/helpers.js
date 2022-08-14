/**
 * @param {Uint8Array} uint8Array
 * @param {number} [start]
 * @param {number} [end]
 */
function uint8ArrayToBase64Url(uint8Array, start, end) {
  start = start || 0
  end = end || uint8Array.byteLength

  const base64 = btoa(
    String.fromCharCode(...uint8Array.subarray(start, end)))
  return base64
    .replace(/\=/g, '') // eslint-disable-line no-useless-escape
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
}

/**
 * Converts the URL-safe base64 encoded |base64UrlData| to an Uint8Array buffer.
 *
 * @param {string} base64UrlData
 */
function base64UrlToUint8Array(base64UrlData) {
  const padding = '='.repeat((4 - base64UrlData.length % 4) % 4)
  const base64 = (base64UrlData + padding)
    .replace(/-/g, '+')
    .replace(/_/g, '/')

  const rawData = atob(base64)
  const buffer = new Uint8Array(rawData.length)

  for (let i = 0; i < rawData.length; ++i) {
    buffer[i] = rawData.charCodeAt(i)
  }
  return buffer
}

/**
 * @param {Uint8Array[]} arrays
 */
function joinUint8Arrays (arrays) {
  const uint8 = /**
   * @param {any} acc
   * @param {{ byteLength: any; }} tArr
   */
 new Uint8Array(arrays.reduce((acc, tArr) => acc + tArr.byteLength, 0))
  let offset = 0
  for (let array of arrays) {
    uint8.set(array, offset)
    offset += array.byteLength
  }
  return uint8
}

/**
 * @param {ArrayBuffer} publicKey
 * @param {Uint8Array} [privateKey]
 */
async function arrayBuffersToCryptoKeys(publicKey, privateKey) {
  // Length, in bytes, of a P-256 field element. Expected format of the private
  // key.
  const PRIVATE_KEY_BYTES = 32

  // Length, in bytes, of a P-256 public key in uncompressed EC form per SEC
  // 2.3.3. This sequence must start with 0x04. Expected format of the
  // public key.
  const PUBLIC_KEY_BYTES = 65

  if (publicKey.byteLength !== PUBLIC_KEY_BYTES) {
    throw new Error('The publicKey is expected to be ' +
      PUBLIC_KEY_BYTES + ' bytes, it was ' + publicKey.byteLength + ' bytes')
  }

  // Cast ArrayBuffer to Uint8Array
  const publicBuffer = new Uint8Array(publicKey)
  if (publicBuffer[0] !== 0x04) {
    throw new Error('The publicKey is expected to start with an ' +
      '0x04 byte.')
  }

  const jwk = {
    kty: 'EC',
    crv: 'P-256',
    x: uint8ArrayToBase64Url(publicBuffer, 1, 33),
    y: uint8ArrayToBase64Url(publicBuffer, 33, 65),
    ext: true,
  }

  const keyPromises = []
  keyPromises.push(crypto.subtle.importKey('jwk', jwk,
    { name: 'ECDH', namedCurve: 'P-256' }, true, []))

  if (privateKey) {
    if (privateKey.byteLength !== PRIVATE_KEY_BYTES) {
      throw new Error('The privateKey is expected to be ' +
        PRIVATE_KEY_BYTES + ' bytes.')
    }

    // d must be defined after the importKey call for public
    jwk.d = uint8ArrayToBase64Url(privateKey)
    keyPromises.push(crypto.subtle.importKey('jwk', jwk,
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']))
  }

  const keys = await Promise.all(keyPromises)

  const keyPair = {
    publicKey: keys[0],
  }
  if (keys.length > 1) {
    keyPair.privateKey = keys[1]
  }
  return keyPair
}


/**
 * @param {CryptoKey} publicKey
 * @param {CryptoKey} [privateKey]
 * @returns {Promise<{publicKey: Uint8Array, privateKey?: Uint8Array}>}
 */
async function cryptoKeysToUint8Array(publicKey, privateKey) {
  const jwk = await crypto.subtle.exportKey('jwk', publicKey)
  const x = base64UrlToUint8Array(jwk.x)
  const y = base64UrlToUint8Array(jwk.y)

  const pubJwk = new Uint8Array(65)
  pubJwk.set([0x04], 0)
  pubJwk.set(x, 1)
  pubJwk.set(y, 33)

  const result = {
    publicKey: pubJwk
  }

  if (privateKey) {
    const jwk = await crypto.subtle.exportKey('jwk', privateKey)
    result.privateKey = base64UrlToUint8Array(jwk.d)
  }

  return result
}

function generateSalt() {
  return crypto.getRandomValues(new Uint8Array(16))
}

export default {
  uint8ArrayToBase64Url,
  base64UrlToUint8Array,
  joinUint8Arrays,
  arrayBuffersToCryptoKeys,
  cryptoKeysToUint8Array,
  generateSalt
}
