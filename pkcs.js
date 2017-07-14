import bigInt from 'big-integer';
import { Ber } from 'asn1';
import * as ASN1 from 'asn1/lib/ber/types.js';
import crypto from 'crypto';
import { uint8ArrayEquals } from './utils.js';

import assert from 'assert';

/**
 * An object specifying the types of hash function accepted by the
 * sign function.
 */
export const hashTypes = Object.freeze({
    sha256: Symbol('SHA-256')
});

export function os2ip(bytes) {
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

export function i2osp(intRepr, expectedLength) {
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

export function rsasp1(privateKey, intMessage) {
    if(intMessage.isNegative() || 
       intMessage.greaterOrEquals(privateKey.n)) {
        throw new Error("message representative out of range");
    }

    // result = intMessage ^ d  (mod n)
    return intMessage.modPow(privateKey.d, privateKey.n);
}

export function rsavp1(publicKey, intSignature) {
    if(intSignature.isNegative() || 
       intSignature.greaterOrEquals(publicKey.n)) {
        throw new Error("message representative out of range");
    }

    // result = intSignature ^ e (mod n)
    return intSignature.modPow(publicKey.e, publicKey.n);
}

export function emsaPkcs1v1_5(hashFn, hashType, expectedLength, message) {
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

export function mgf1(hashFn, expectedLength, seed) {
    if(expectedLength > Math.pow(2, 32)) {
        throw new Error('mask too long');
    }

    const hashSize = hashFn(Uint8Array.of(0), true).byteLength;
    const count = Math.ceil(expectedLength / hashSize);
    const result = new Uint8Array(hashSize * count);
    for(let i = 0; i < count; ++i) {
        const c = i2osp(bigInt(i), 4);
        const value = hashFn(Uint8Array.of(...seed, ...c), true);
        result.set(value, i * hashSize);
    }
    return result.subarray(0, expectedLength);
}

export function emsaPssEncode(hashFn, 
                              hashType, 
                              mgf, 
                              saltLength, 
                              expectedLengthBits, 
                              message) {
    const expectedLength = Math.ceil(expectedLengthBits / 8);

    const digest1 = hashFn(message, true);
    if(expectedLength < (digest1.length + saltLength + 2)) {
        throw new Error('encoding error');
    }

    const salt = crypto.randomBytes(saltLength);
    const m = Uint8Array.of(...(new Uint8Array(8)), 
                            ...digest1, 
                            ...salt);
    const digest2 = hashFn(m, true);
    const ps = new Uint8Array(expectedLength - saltLength - digest2.length - 2);
    const db = Uint8Array.of(...ps, 0x01, ...salt);
    const dbMask = mgf(db.length, digest2);
    const masked = db.map((value, index) => value ^ dbMask[index]);
    
    const zeroBits = 8 * expectedLength - expectedLengthBits;
    const zeroBitsMask = 0xFF >>> zeroBits;
    masked[0] &= zeroBitsMask;
    
    return Uint8Array.of(...masked, ...digest2, 0xbc);
}

export function emsaPssVerify(hashFn, 
                              hashType, 
                              mgf, 
                              saltLength, 
                              expectedLengthBits, 
                              message,
                              verificationMessage) {
    const expectedLength = Math.ceil(expectedLengthBits / 8);
    
    const digest1 = hashFn(message, true);
    if(expectedLength < (digest1.length + saltLength + 2)) {
        return false;
    }

    if(verificationMessage.length === 0) {
        return false;
    }

    if(verificationMessage[verificationMessage.length - 1] !== 0xBC) {
        return false;
    }

    const maskedLength = expectedLength - digest1.length - 1;
    const masked = verificationMessage.subarray(0, maskedLength);
    const digest2 = verificationMessage.subarray(maskedLength,
                                                 maskedLength + digest1.length);
    
    const zeroBits = 8 * expectedLength - expectedLengthBits;
    const zeroBitsMask = 0xFF >>> zeroBits;
    if((masked[0] & (~zeroBitsMask)) !== 0) {
        return false;
    }

    const dbMask = mgf(maskedLength, digest2);
    const db = masked.map((value, index) => value ^ dbMask[index]);
    db[0] &= zeroBitsMask;

    const zeroCheckLength = expectedLength - (digest1.length + saltLength + 2);
    if(!db.subarray(0, zeroCheckLength).every(v => v === 0) || 
       db[zeroCheckLength] !== 0x01) {
        return false;
    }

    const salt = db.subarray(db.length - saltLength);
    const m = Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 0, ...digest1, ...salt);
    const expectedDigest = hashFn(m, true);

    return uint8ArrayEquals(digest2, expectedDigest);
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
