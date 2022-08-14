import HKDF from './hkdf.js'
import helpers from './helpers.js'

/**
 * @param {{ getKey: (arg0: any) => any; keys: { [x: string]: string; }; }} sub
 * @param {string} key
 */
const getKey = (sub, key) => {
  return typeof sub.getKey === 'function'
    ? sub.getKey(key)
    : helpers.base64UrlToUint8Array(sub.keys[key])
}

const utf8Encoder = new TextEncoder()

export default class EncryptionHelperAES128GCM {
  /**
   * @param {{
   *   vapidKeys: { publicKey: string, privateKey: string };
   *   subject: string;
   *   serverKeys?: { publicKey: string, privateKey: string };
   *   salt?: Uint8Array;
   * }} options
   */
  constructor (options) {
    this._b64ServerKeys = options.serverKeys
    this._b64Salt = options.salt
    this.subject = options.subject
    this.vapidKeys = {
      publicKey: helpers.base64UrlToUint8Array(options.vapidKeys.publicKey),
      privateKey: helpers.base64UrlToUint8Array(options.vapidKeys.privateKey)
    }
  }

  getServerKeys() {
    if (this._b64ServerKeys) {
      return helpers.arrayBuffersToCryptoKeys(
        helpers.base64UrlToUint8Array(this._b64ServerKeys.publicKey),
        helpers.base64UrlToUint8Array(this._b64ServerKeys.privateKey)
      )
    }

    return EncryptionHelperAES128GCM.generateServerKeys()
  }

  getSalt() {
    if (this._b64Salt) {
      return helpers.base64UrlToUint8Array(this._b64Salt)
    }

    return helpers.generateSalt()
  }

  /**
   * @param {{ endpoint: string; }} subscription
   * @param {Uint8Array} payload
   */
  async getRequestDetails (subscription, payload) {
    let endpoint = subscription.endpoint
    const useV2 = endpoint.indexOf('https://fcm.googleapis.com') === 0

    // Latest spec changes for VAPID is implemented on this custom FCM
    // endpoint. This is experimental and SHOULD NOT BE USED IN PRODUCTION
    // web apps.
    //
    // Need to get a proper feature detect in place for these vapid changes
    // https://github.com/mozilla-services/autopush/issues/879
    if (useV2) {
      endpoint = endpoint.replace('fcm/send', 'wp')
    }

    /** @type {{default: import('./vapid-helper-2.js').default }} */
    const { default: createVapidAuthHeader } = await import(useV2
      ? './vapid-helper-2.js'
      : './vapid-helper-1.js'
    )

    const vapidHeaders = await createVapidAuthHeader(
      this.vapidKeys,
      subscription.endpoint,
      this.subject
    )

    const encryptedPayloadDetails = await this.encryptPayload(subscription, payload)
    let body = null, method = 'GET'

    const headers = {
      TTL: 60
    }

    if (encryptedPayloadDetails) {
      body = encryptedPayloadDetails.cipherText
      method = 'POST'
      headers['Content-Encoding'] = 'aes128gcm'
    } else {
      headers['Content-Length'] = 0
    }

    if (vapidHeaders) {
      Object.assign(headers, vapidHeaders)
    }

    // Return it as they appare in fetch arguments
    // so that you could do fetch(...args)
    return [ endpoint, { headers, body, method } ]
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
      serverKeys.publicKey
    )
    const encryptionKeys = await this._generateEncryptionKeys(
      subscription, salt, serverKeys
    )

    const contentEncryptionCryptoKey = await crypto.subtle.importKey('raw',
      encryptionKeys.contentEncryptionKey, 'AES-GCM', true,
      ['decrypt', 'encrypt'])
    encryptionKeys.contentEncryptionCryptoKey = contentEncryptionCryptoKey

    const paddingBytes = 0
    const paddingUnit8Array = new Uint8Array(1 + paddingBytes)
    paddingUnit8Array.fill(0)
    paddingUnit8Array[0] = 0x02

    const recordUint8Array = helpers.joinUint8Arrays([
      payloadUint8Array,
      paddingUnit8Array
    ])

    const algorithm = {
      name: 'AES-GCM',
      tagLength: 128,
      iv: encryptionKeys.nonce
    }

    const encryptedPayloadArrayBuffer = await crypto.subtle.encrypt(
      algorithm, encryptionKeys.contentEncryptionCryptoKey,
      recordUint8Array)

    const payloadWithHeaders = await this._addEncryptionContentCodingHeader(
      encryptedPayloadArrayBuffer,
      serverKeys,
      salt)

    return {
      cipherText: payloadWithHeaders,
      salt: helpers.uint8ArrayToBase64Url(salt),
      publicServerKey: helpers.uint8ArrayToBase64Url(exportedServerKeys.publicKey)
    }
  }

  static generateServerKeys() {
    // 'true' is to make the keys extractable
    return crypto.subtle.generateKey({
      name: 'ECDH',
      namedCurve: 'P-256'
    }, true, ['deriveBits'])
  }

  static async generateB64ServerKeys() {
    const keys = await EncryptionHelperAES128GCM.generateServerKeys()
    const uint8s = await helpers.cryptoKeysToUint8Array(keys.publicKey, keys.privateKey)

    return {
      privateKey: helpers.uint8ArrayToBase64Url(uint8s.privateKey),
      publicKey: helpers.uint8ArrayToBase64Url(uint8s.publicKey)
    }
  }

  /**
   * @param {ArrayBuffer} encryptedPayloadArrayBuffer
   * @param {{ publicKey: CryptoKey; }} serverKeys
   * @param {Uint8Array} salt
   */
  async _addEncryptionContentCodingHeader(
    encryptedPayloadArrayBuffer, serverKeys, salt
  ) {
    const keys = await helpers.cryptoKeysToUint8Array(serverKeys.publicKey)
    // Maximum record size.
    const recordSizeUint8Array = new Uint8Array([0x00, 0x00, 0x10, 0x00])

    const serverPublicKeyLengthBuffer = new Uint8Array(1)
    serverPublicKeyLengthBuffer[0] = keys.publicKey.byteLength

    const uint8arrays = [
      salt,
      // Record Size
      recordSizeUint8Array,
      // Service Public Key Length
      serverPublicKeyLengthBuffer,
      // Server Public Key
      keys.publicKey,
      new Uint8Array(encryptedPayloadArrayBuffer),
    ]

    const joinedUint8Array = helpers.joinUint8Arrays(uint8arrays)
    return joinedUint8Array.buffer
  }

  /**
   * @param {any} subscription
   * @param {ArrayBuffer} salt
   * @param {{ publicKey: CryptoKey; }} serverKeys
   */
  async _generateEncryptionKeys(subscription, salt, serverKeys) {
    const infoResults = await Promise.all([
      this._generatePRK(subscription, serverKeys),
      this._generateCEKInfo(),
      this._generateNonceInfo(),
    ])

    const prk = infoResults[0]
    const cekInfo = infoResults[1]
    const nonceInfo = infoResults[2]

    const cekHKDF = new HKDF(prk, salt)
    const nonceHKDF = new HKDF(prk, salt)
    const keyResults = await Promise.all([
      cekHKDF.generate(cekInfo, 16),
      nonceHKDF.generate(nonceInfo, 12),
    ])
    return {
      contentEncryptionKey: keyResults[0],
      nonce: keyResults[1],
    }
  }

  _generateCEKInfo() {
    const contentEncoding8Array = utf8Encoder.encode('Content-Encoding: aes128gcm')
    const paddingUnit8Array = new Uint8Array(1)
    return helpers.joinUint8Arrays([
      contentEncoding8Array,
      paddingUnit8Array,
    ])
  }

  _generateNonceInfo() {
    const contentEncoding8Array = utf8Encoder.encode('Content-Encoding: nonce')
    const paddingUnit8Array = new Uint8Array(1)
    return helpers.joinUint8Arrays([
      contentEncoding8Array,
      paddingUnit8Array,
    ])
  }

  /**
   * @param {any} subscription
   * @param {any} serverKeys
   */
  async _generatePRK(subscription, serverKeys) {
    const sharedSecret = await this._getSharedSecret(subscription, serverKeys)

    const keyInfoUint8Array = await this._getKeyInfo(subscription, serverKeys)
    const hkdf = new HKDF(
      sharedSecret,
      getKey(subscription, 'auth')
    )
    return hkdf.generate(keyInfoUint8Array, 32)
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
      public: keys.publicKey,
    }

    return crypto.subtle.deriveBits(algorithm, serverKeys.privateKey, 256)
  }

  /**
   * @param {any} subscription
   * @param {{ publicKey: CryptoKey; }} serverKeys
   */
  async _getKeyInfo(subscription, serverKeys) {
    const keyInfo = await helpers.cryptoKeysToUint8Array(serverKeys.publicKey)
    return helpers.joinUint8Arrays([
      utf8Encoder.encode('WebPush: info'),
      new Uint8Array(1),
      new Uint8Array(getKey(subscription, 'p256dh')),
      keyInfo.publicKey,
    ])
  }
}
