import HKDF from './hkdf.js'
import helpers from './helpers.js'

/**
 * @param {*} sub
 * @param {string} key
 */
const getKey = (sub, key) => {
  return typeof sub?.keys?.[key] === 'string'
    ? helpers.base64UrlToUint8Array(sub.keys[key])
    : sub.getKey(key)
}

export default class EncryptionHelperAESGCM {
  constructor (options) {
    this.b64ServerKeys = options.serverKeys
    this.b64Salt = options.salt
    this.vapidKeys = {
      publicKey: helpers.base64UrlToUint8Array(options.vapidKeys.publicKey),
      privateKey: helpers.base64UrlToUint8Array(options.vapidKeys.privateKey)
    }
  }

  getServerKeys() {
    if (this.b64ServerKeys) {
      return helpers.arrayBuffersToCryptoKeys(
        helpers.base64UrlToUint8Array(this.b64ServerKeys.publicKey),
        helpers.base64UrlToUint8Array(this.b64ServerKeys.privateKey),
      )
    }

    return EncryptionHelperAESGCM.generateServerKeys()
  }

  getSalt() {
    if (this.b64Salt) {
      return helpers.base64UrlToUint8Array(this.b64Salt)
    }

    return helpers.generateSalt()
  }

  /**
   * @param {{ endpoint: string; }} subscription
   * @param {any} payloadText
   */
  async getRequestDetails(subscription, payloadText) {
    const { default: createVapidAuthHeader } = await import('./vapid-helper-1.js')

    const vapidHeaders = await createVapidAuthHeader(
      this.vapidKeys,
      subscription.endpoint,
      'mailto:jimmy@warting.se'
    )

    const encryptedPayloadDetails = await this.encryptPayload(
      subscription, payloadText
    )

    let body = null, method = 'GET'
    const headers = {
      TTL: 60
    }

    if (encryptedPayloadDetails) {
      body = encryptedPayloadDetails.cipherText
      method = 'POST'

      headers.Encryption = `salt=${encryptedPayloadDetails.salt}`
      headers['Crypto-Key'] = `dh=${encryptedPayloadDetails.publicServerKey}`
      headers['Content-Encoding'] = 'aesgcm'
    } else {
      headers['Content-Length'] = 0
    }

    if (vapidHeaders) {
      Object.assign(headers, vapidHeaders)
    }

    return [ subscription.endpoint, { headers, body, method } ]
  }

  /**
   * @param {any} subscription
   * @param {Uint8Array} payloadUint8Array
   */
  async encryptPayload(subscription, payloadUint8Array) {
    if (payloadUint8Array.byteLength === 0) {
      return Promise.resolve(null)
    }

    const salt = this.getSalt()

    const serverKeys = await this.getServerKeys()

    const exportedServerKeys = await helpers.cryptoKeysToUint8Array(
      serverKeys.publicKey)
    const encryptionKeys = await this._generateEncryptionKeys(
      subscription, salt, serverKeys)
    const contentEncryptionCryptoKey = await crypto.subtle.importKey('raw',
      encryptionKeys.contentEncryptionKey, 'AES-GCM', true,
      ['decrypt', 'encrypt'])
    encryptionKeys.contentEncryptionCryptoKey = contentEncryptionCryptoKey

    const paddingBytes = 0
    const paddingUnit8Array = new Uint8Array(2 + paddingBytes)
    const recordUint8Array = new Uint8Array(
      paddingUnit8Array.byteLength + payloadUint8Array.byteLength)
    recordUint8Array.set(paddingUnit8Array, 0)
    recordUint8Array.set(payloadUint8Array, paddingUnit8Array.byteLength)

    const algorithm = {
      name: 'AES-GCM',
      tagLength: 128,
      iv: encryptionKeys.nonce,
    }

    const encryptedPayloadArrayBuffer = await crypto.subtle.encrypt(
      algorithm, encryptionKeys.contentEncryptionCryptoKey,
      recordUint8Array,
    )

    return {
      cipherText: encryptedPayloadArrayBuffer,
      salt: helpers.uint8ArrayToBase64Url(salt),
      publicServerKey: helpers.uint8ArrayToBase64Url(
        exportedServerKeys.publicKey),
    }
  }

  static generateServerKeys() {
    // 'true' is to make the keys extractable
    return crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' },
      true, ['deriveBits'])
  }

  /**
   * @param {any} subscription
   * @param {ArrayBuffer} salt
   * @param {{ publicKey: CryptoKey; }} serverKeys
   */
  async _generateEncryptionKeys(subscription, salt, serverKeys) {
    const results = await Promise.all([
      this._generatePRK(subscription, serverKeys),
      this._generateCEKInfo(subscription, serverKeys),
      this._generateNonceInfo(subscription, serverKeys),
    ])

    const prk = results[0]
    const cekInfo = results[1]
    const nonceInfo = results[2]

    const cekHKDF = new HKDF(prk, salt)
    const nonceHKDF = new HKDF(prk, salt)

    const finalKeys = await Promise.all([
      cekHKDF.generate(cekInfo, 16),
      nonceHKDF.generate(nonceInfo, 12),
    ])

    return {
      contentEncryptionKey: finalKeys[0],
      nonce: finalKeys[1],
    }
  }

  /**
   * @param {any} subscription
   * @param {{ publicKey: any; }} serverKeys
   */
  async _generateContext(subscription, serverKeys) {
    const cryptoKeys = await helpers.arrayBuffersToCryptoKeys(
      getKey(subscription, 'p256dh'))
    const keysAsCryptoKeys = {
      clientPublicKey: cryptoKeys.publicKey,
      serverPublicKey: serverKeys.publicKey,
    }
    const keysAsUint8 = await Promise.all([
      helpers.cryptoKeysToUint8Array(keysAsCryptoKeys.clientPublicKey),
      helpers.cryptoKeysToUint8Array(keysAsCryptoKeys.serverPublicKey),
    ])
    const keys = {
      clientPublicKey: keysAsUint8[0].publicKey,
      serverPublicKey: keysAsUint8[1].publicKey,
    }

    const utf8Encoder = new TextEncoder()
    const labelUnit8Array = utf8Encoder.encode('P-256')
    const paddingUnit8Array = new Uint8Array(1)

    const clientPublicKeyLengthUnit8Array = new Uint8Array(2)
    clientPublicKeyLengthUnit8Array[0] = 0x00
    clientPublicKeyLengthUnit8Array[1] = keys.clientPublicKey.byteLength

    const serverPublicKeyLengthBuffer = new Uint8Array(2)
    serverPublicKeyLengthBuffer[0] = 0x00
    serverPublicKeyLengthBuffer[1] = keys.serverPublicKey.byteLength

    return helpers.joinUint8Arrays([
      labelUnit8Array,
      paddingUnit8Array,
      clientPublicKeyLengthUnit8Array,
      keys.clientPublicKey,
      serverPublicKeyLengthBuffer,
      keys.serverPublicKey,
    ])
  }

  /**
   * @param {any} subscription
   * @param {any} serverKeys
   */
  async _generateCEKInfo(subscription, serverKeys) {
    const utf8Encoder = new TextEncoder()
    const contentEncoding8Array = utf8Encoder.encode('Content-Encoding: aesgcm')
    const paddingUnit8Array = new Uint8Array(1)
    const contextBuffer = await this._generateContext(subscription, serverKeys)

    return helpers.joinUint8Arrays([
      contentEncoding8Array,
      paddingUnit8Array,
      contextBuffer,
    ])
  }

  /**
   * @param {any} subscription
   * @param {any} serverKeys
   */
  async _generateNonceInfo(subscription, serverKeys) {
    const utf8Encoder = new TextEncoder()
    const contentEncoding8Array = utf8Encoder.encode('Content-Encoding: nonce')
    const paddingUnit8Array = new Uint8Array(1)
    const contextBuffer = await this._generateContext(subscription, serverKeys)

    return helpers.joinUint8Arrays([
      contentEncoding8Array,
      paddingUnit8Array,
      contextBuffer,
    ])
  }

  /**
   * @param {any} subscription
   * @param {any} serverKeys
   */
  async _generatePRK(subscription, serverKeys) {
    const sharedSecret = await this._getSharedSecret(subscription, serverKeys)
    const utf8Encoder = new TextEncoder()
    const authInfoUint8Array = utf8Encoder.encode('Content-Encoding: auth\0')
    const hkdf = new HKDF(sharedSecret, getKey(subscription, 'auth'))

    return hkdf.generate(authInfoUint8Array, 32)
  }

  /**
   * @param {any} subscription
   * @param {{ privateKey: CryptoKey; }} serverKeys
   */
  async _getSharedSecret(subscription, serverKeys) {
    const p256dh = getKey(subscription, 'p256dh')
    const keys = await helpers.arrayBuffersToCryptoKeys(p256dh)

    if (!(keys.publicKey instanceof CryptoKey)) {
      throw new Error('The publicKey must be a CryptoKey.')
    }

    const algorithm = {
      name: 'ECDH',
      namedCurve: 'P-256',
      public: keys.publicKey
    }

    return crypto.subtle.deriveBits(algorithm, serverKeys.privateKey, 256)
  }
}
