'use strict'

const ecurve = require('ecurve')
const secp256k1 = ecurve.getCurveByName('secp256k1')
const BigInt = require('bigi')
const SHA256 = require('crypto-js/sha256')

/**
 * Constructor
1* @param {BigInteger} d Private key
 * @param {Point} Q Public key
 */
function KeyPair (d, Q) {
  if (d) {
    if (d.signum() <= 0) throw new Error('Private key must be greater than 0')
    if (d.compareTo(secp256k1.n) >= 0) throw new Error('Private key must be less than the curve order')
    if (Q) throw new TypeError('Unexpected publickey parameter')

    this.d = d
  } else {
    this.__Q = Q
  }
}

Object.defineProperty(KeyPair.prototype, 'Q', {
  get: () => {
    if (!this.__Q && this.d) {
      this.__Q = secp256k1.G.multiply(this.d)
    }

    return this.__Q
  }
})

KeyPair.fromSeed = (seed) => {
  const hash = SHA256(seed).toString()
  const d = BigInt(hash, 16)
  if (d.signum() <= 0 || d.compareTo(secp256k1.n) >= 0) {
    throw new Error('Seed cannot resolve to a compatible private key')
  } else {
    return new KeyPair(d, null)
  }
}

module.exports = KeyPair

