const keypair = require('./KeyPair')

const dm = keypair.fromSeed('mess')
console.log(dm.Q)
