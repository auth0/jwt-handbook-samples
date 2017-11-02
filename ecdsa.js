import bigInt from 'big-integer';
import { hashTypes } from './sha256.js';

bigInt.prototype.fixedMod = function(fixedModulus) {
    const result = this.mod(fixedModulus);
    return result.isNegative() ? fixedModulus.add(result) : result;
}

// Curve P-256, FIPS 186-4
// http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
const p256 = {
    q: bigInt('00ffffffff00000001000000000000' +
              '000000000000ffffffffffffffffff' +
              'ffffff', 16),
    // order of base point
    n: bigInt('115792089210356248762697446949407573529996955224135760342' +
              '422259061068512044369'),     
    // base point
    G: { 
        x: bigInt('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0' +
                  'f4a13945d898c296', 16),
        y: bigInt('4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ece' +
                  'cbb6406837bf51f5', 16)
    },
    //a: bigInt(-3)
    a: bigInt('00ffffffff00000001000000000000' +
              '000000000000ffffffffffffffffff' +
              'fffffc', 16),
    b: bigInt('5ac635d8aa3a93e7b3ebbd55769886' +
              'bc651d06b0cc53b0f63bce3c3e27d2' +
              '604b', 16)
};
p256.nMin1 = p256.n.subtract(1);

function ecDouble(p, m) {
    if(p.x.isZero() && p.y.isZero()) {
        return p;
    }

    const s = p.x.multiply(3).multiply(p.x).add(p256.a)
               .multiply(p.y.multiply(2).modInv(m)).fixedMod(m);
    const x = s.multiply(s).subtract(p.x.multiply(2)).fixedMod(m);
    const y = s.multiply(p.x.subtract(x)).subtract(p.y).fixedMod(m);

    return {
        x: x,
        y: y
    };
}

function ecAdd(a, b, m) {
    // (0, 0) is the identity element
    if(a.x.isZero() && a.y.isZero()) {
        return b;
    }
    // (0, 0) is the identity element
    if(b.x.isZero() && b.y.isZero()) {
        return a;
    }    
    if(a.x.compare(b.x) === 0) {
        // (a.x == b.x && a.y == -b.y)
        if(a.y.compare(b.y.multiply(-1).fixedMod(m)) === 0) {
            return {
                x: bigInt(0),
                y: bigInt(0)
            };
        // (a.x == b.x && a.y == b.y)
        } else if (a.y.compare(b.y) === 0) {
            return ecDouble(a);
        }
    }

    // slope = (b.y - a.y) / (b.x - a.x)
    const s = b.y.subtract(a.y).multiply(b.x.subtract(a.x).modInv(m))
               .fixedMod(m);
    // x = s^2 - a.x - b.x
    const x = s.multiply(s).subtract(a.x).subtract(b.x).fixedMod(m);
    // y = s(a.x - x) - a.y
    const y = s.multiply(a.x.subtract(x)).subtract(a.y).fixedMod(m);

    return {
        x: x,
        y: y
    };
}

function ecMultiply(point, factor, modulus) {
    let p = Object.assign({}, point);
    let result = {
        x: bigInt(0),
        y: bigInt(0)
    };

    for(let f = bigInt(factor); !f.isZero(); f = f.shiftRight(1)) {
        if(f.isOdd()) {
            result = ecAdd(result, p, modulus);
        }
        p = ecDouble(p, modulus);
    }

    return result;
}

function isValidPoint(point) {
    // Curve equation: y^2 = x^3 + ax + b
    const xpow3 = point.x.modPow(3, p256.q);
    const ax = point.x.multiply(p256.a).fixedMod(p256.q);
    const right = xpow3.add(ax).add(p256.b).fixedMod(p256.q);
    const left = point.y.modPow(2, p256.q);

    return right.equals(left);
}

export function sign(privateKey, hashFn, hashType, message) {
    if(hashType !== hashTypes.sha256) {
        throw new Error('unsupported hash type');
    }

    // Algorithm as described in ANS X9.62-1998, 5.3

    const e = bigInt(hashFn(message), 16);
    
    let r;
    let s;
    do {
        let k;
        do {
            // Warning: use a secure RNG here
            k = bigInt.randBetween(1, p256.nMin1);
            const point = ecMultiply(p256.G, k, p256.q);
            r = point.x.fixedMod(p256.n);
        } while(r.isZero());

        const dr = r.multiply(privateKey.d);
        const edr = dr.add(e);
        s = edr.multiply(k.modInv(p256.n)).fixedMod(p256.n);
    } while(s.isZero());

    return {
        r: r,
        s: s
    };
}

export function verify(publicKey, hashFn, hashType, message, signature) {
    if(hashType !== hashTypes.sha256) {
        throw new Error('unsupported hash type');
    }    

    if(signature.r.compare(1) === -1 || signature.r.compare(p256.nMin1) === 1 ||
       signature.s.compare(1) === -1 || signature.s.compare(p256.nMin1) === 1) {
        return false;
    }

    // check whether the public key is a valid curve point:
    // http://blogs.adobe.com/security/2017/03/critical-vulnerability-uncovered-in-json-encryption.html
    if(!isValidPoint(publicKey.Q)) {
        return false;
    }

    // Algorithm as described in ANS X9.62-1998, 5.4

    const e = bigInt(hashFn(message), 16);

    const c = signature.s.modInv(p256.n);
    const u1 = e.multiply(c).fixedMod(p256.n);
    const u2 = signature.r.multiply(c).fixedMod(p256.n);

    const pointA = ecMultiply(p256.G, u1, p256.q);
    const pointB = ecMultiply(publicKey.Q, u2, p256.q);
    const point = ecAdd(pointA, pointB, p256.q);

    const v = point.x.fixedMod(p256.n);
    return v.compare(signature.r) === 0;
}

export function getPublicKey(privateKey) {
    return ecMultiply(p256.G, privateKey.d, p256.q);
}
