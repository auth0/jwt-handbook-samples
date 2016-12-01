import bigInt from 'big-integer';
import { Ber } from 'asn1';
import * as ASN1 from 'asn1/lib/ber/types.js';

import assert from 'assert';

/**
 * An object specifying the types of hash function accepted by the
 * sign function.
 */
export const hashTypes = Object.freeze({
    sha256: Symbol('SHA-256')
});

/**
 * Produces a signature for a message using the RSA algorithm as defined
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
export function sign(privateKey, hashFn, hashType, message) {
    const encodedMessage = 
        emsaPkcs1v1_5(hashFn, hashType, privateKey.size / 8, message);
    const intMessage = os2ip(encodedMessage);
    const intSignature = rsasp1(privateKey, intMessage);
    const signature = i2osp(intSignature, privateKey.size / 8);
    return signature;
}

function os2ip(bytes) {
    let result = bigInt();

    bytes.forEach((b, i) => {
        // result += b * Math.pow(256, bytes.length - 1 - i);
        result = result.add(
            bigInt(b).multiply(
                bigInt(256).pow(bytes.length - i - 1)
            )
        );
    });

    return result;
}

function i2osp(intRepr, expectedLength) {
    if(intRepr.greaterOrEquals(bigInt(256).pow(expectedLength))) {
        throw new Error('integer too large');
    }

    const result = new Uint8Array(expectedLength);
    let remainder = bigInt(intRepr);
    for(let i = expectedLength - 1; i >= 0; --i) {
        const position = bigInt(256).pow(i);
        const quotrem = remainder.divmod(position);
        remainder = quotrem.remainder;
        result[result.length - 1 - i] = quotrem.quotient.valueOf();
    }

    return result;
}

function rsasp1(privateKey, intMessage) {
    if(intMessage.isNegative() || 
       intMessage.greaterOrEquals(privateKey.n)) {
        throw new Error("message representative out of range");
    }

    // result = intMessage ^ d  (mod n)
    return intMessage.modPow(privateKey.d, privateKey.n);
}

function emsaPkcs1v1_5(hashFn, hashType, expectedLength, message) {
    if(hashType !== hashTypes.sha256) {
        throw new Error("Unsupported hash type");
    }

    const digest = hashFn(message, true);

    // DER is a stricter set of BER, this (fortunately) works:
    const berWriter = new Ber.Writer();
    berWriter.startSequence();
        berWriter.startSequence();
        // SHA-256 OID
        berWriter.writeOID("2.16.840.1.101.3.4.2.1");
        berWriter.writeNull();
        berWriter.endSequence();
    berWriter.writeBuffer(Buffer.from(digest), ASN1.OctetString);
    berWriter.endSequence();

    // T is the name of this element in RFC 3447
    const t = berWriter.buffer;

    if(expectedLength < (t.length + 11)) {
        throw new Error('intended encoded message length too short');
    }

    const ps = new Uint8Array(expectedLength - t.length - 3);
    ps.fill(0xff);
    assert.ok(ps.length >= 8);

    return Uint8Array.of(0x00, 0x01, ...ps, 0x00, ...t);
}

if(process.env.TEST) {
    //Test 1
    const msg = Uint8Array.of(1, 2, 3, 4, 5);
    const intRepr = os2ip(msg);
    const intReprExpected = 4328719365;
    assert.equal(intRepr, intReprExpected);

    //Test 2
    const octets = i2osp(intRepr, msg.length);
    octets.forEach((v, i) => {
        assert.equal(v, msg[i]);
    });

    // Test 3
    const zeroes = new Uint8Array(32);
    zeroes.fill(0);
    const expected = Uint8Array.of(
        0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 
        0x00, 0x04, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00);

    const berWriter = new Ber.Writer();
    berWriter.startSequence();
        berWriter.startSequence();
        berWriter.writeOID("2.16.840.1.101.3.4.2.1");
        berWriter.writeNull();
        berWriter.endSequence();
    berWriter.writeBuffer(Buffer.from(zeroes), ASN1.OctetString);
    berWriter.endSequence();

    expected.forEach((v, i) => {
        assert.equal(v, berWriter.buffer[i]);
    });
}
