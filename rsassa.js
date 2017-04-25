import { 
    os2ip,
    i2osp,
    rsasp1,
    emsaPkcs1v1_5,
    mgf1,
    emsaPssEncode,
    hashTypes
 } from './pkcs';

export { hashTypes };

/**
 * Produces a signature for a message using the RSASSA algorithm as defined
 * in PKCS#1.
 * @param {privateKey} RSA private key, an object with 
 *                     three members: size (size in bits), n (the modulus) and 
 *                     d (the private exponent), both bigInts 
 *                     (big-integer library).
 * @param {hashFn} the hash function as required by PKCS#1, 
 *                 it should take a Uint8Array and return a Uint8Array
 * @param {hashType} A symbol identifying the type of hash function passed. 
 *                   For now, only "SHA-256" is supported. See the "hashTypes"
 *                   object for possible values.
 * @param {message} A String or Uint8Array with arbitrary data to sign 
 * @return {Uint8Array} The signature as a Uint8Array
 */
export function signPkcs1v1_5(privateKey, hashFn, hashType, message) {
    if(hashType !== hashTypes.sha256) {
        throw new Error('unsupported hash type');
    }
    
    const encodedMessage = 
        emsaPkcs1v1_5(hashFn, hashType, privateKey.size / 8, message);
    const intMessage = os2ip(encodedMessage);
    const intSignature = rsasp1(privateKey, intMessage);
    const signature = i2osp(intSignature, privateKey.size / 8);
    return signature;
}

/**
 * Produces a signature for a message using the RSASSA algorithm as defined
 * in PKCS using PSS.
 * @param {privateKey} RSA private key, an object with 
 *                     three members: size (size in bits), n (the modulus) and 
 *                     d (the private exponent), both bigInts 
 *                     (big-integer library).
 * @param {hashFn} the hash function as required by PKCS#1, 
 *                 it should take a Uint8Array and return a Uint8Array
 * @param {hashType} A symbol identifying the type of hash function passed. 
 *                   For now, only "SHA-256" is supported. See the "hashTypes"
 *                   object for possible values.
 * @param {message} A String or Uint8Array with arbitrary data to sign 
 * @return {Uint8Array} The signature as a Uint8Array
 */
export function signPss(privateKey, hashFn, hashType, message) {
    if(hashType !== hashTypes.sha256) {
        throw new Error('unsupported hash type');
    }

    const encodedMessage = emsaPssEncode(hashFn, 
                                         hashType, 
                                         mgf1.bind(null, hashFn),
                                         256 / 8, //size of hash
                                         privateKey.size - 1,
                                         message);
    const intMessage = os2ip(encodedMessage);
    const intSignature = rsasp1(privateKey, intMessage);
    const signature = i2osp(intSignature, privateKey.size / 8);
    return signature;
}

export const pkcs1v1_5 = Object.freeze({
    sign: signPkcs1v1_5,
    verify: undefined
});

export const pss = Object.freeze({
    sign: signPss,
    verify: undefined
});
