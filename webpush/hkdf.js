import HMAC from './hmac.js'

export default class HKDF {
  _ikm
  _hmac

  /**
   * @param {ArrayBuffer} ikm
   * @param {ArrayBuffer} salt
   */
  constructor (ikm, salt) {
    this._ikm = ikm
    this._hmac = new HMAC(salt)
  }

  /**
   * @param {Uint8Array} info
   * @param {number} byteLength
   */
  async generate (info, byteLength) {
    const fullInfoBuffer = new Uint8Array(info.byteLength + 1)
    fullInfoBuffer.set(info, 0)
    fullInfoBuffer.set(new Uint8Array([1]), info.byteLength)

    const prk = await this._hmac.sign(this._ikm)
    const nextHmac = new HMAC(prk)
    const nextPrk = await nextHmac.sign(fullInfoBuffer)
    return nextPrk.slice(0, byteLength)
  }
}
