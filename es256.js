import bigInt from 'big-integer';
import { sign, verify, getPublicKey } from './ecdsa.js';
import sha256 from './sha256.js';
import { i2osp, os2ip } from './pkcs.js';
import * as base64 from './base64.js';
import { b64, stringToUtf8, isString, unb64 } from './utils.js';

export default function jwtEncode(header, payload, privateKey) {
    if(typeof header !== 'object' || typeof payload !== 'object') {
        throw new Error('header and payload must be objects');
    }

    header.alg = 'ES256';

    const encHeader = b64(JSON.stringify(header));
    const encPayload = b64(JSON.stringify(payload));
    const jwtUnprotected = `${encHeader}.${encPayload}`;
    const ecSignature = sign(privateKey, sha256,
                             sha256.hashType, stringToUtf8(jwtUnprotected));
    const ecR = i2osp(ecSignature.r, 32);
    const ecS = i2osp(ecSignature.s, 32);
    const signature = b64(Uint8Array.of(...ecR, ...ecS));

    return `${jwtUnprotected}.${signature}`;
}

export function jwtVerifyAndDecode(jwt, publicKey) {
    if(!isString(jwt)) {
        throw new TypeError('jwt must be a string');
    }

    const split = jwt.split('.');
    if(split.length !== 3) {
        throw new Error('Invalid JWT format');
    }

    const header = JSON.parse(unb64(split[0]));
    if(header.alg !== 'ES256') {
        throw new Error(`Wrong algorithm: ${header.alg}`);
    }

    const jwtUnprotected = stringToUtf8(`${split[0]}.${split[1]}`);

    const signature = base64.decode(split[2]);
    const ecR = signature.slice(0, 32);
    const ecS = signature.slice(32);
    const ecSignature = {
        r: os2ip(ecR),
        s: os2ip(ecS)
    };

    const valid = verify(publicKey, 
                         sha256,
                         sha256.hashType,
                         jwtUnprotected,
                         ecSignature);

    return {
        header: header,
        payload: JSON.parse(unb64(split[1])),
        valid: valid
    };
}

if(process.env.TEST) {
    const privateKey = {
        d: bigInt('7af6732f581d005afcf216f6385ff6' +
                  '371029242cc60840dd7d2a7a5503b7' +
                  'd21c', 16)
    };
    
    const publicKey = {
        Q: getPublicKey(privateKey)
    };
    
    console.log('Qx: ', publicKey.Q.x.toString(16));
    console.log('Qy: ', publicKey.Q.y.toString(16));

    const message = Uint8Array.of(0,1,2,3,4,5,6,7,8,9,10);
    const signature = sign(privateKey, sha256, sha256.hashType, message);
    console.log(verify(publicKey, sha256, sha256.hashType, message, signature));

    const encoded = jwtEncode({}, {sub: "test@test.com"}, privateKey);
    const decoded = jwtVerifyAndDecode(encoded, publicKey);
    
    console.log(`Encoded: ${encoded}`);
    console.log(`Decoded: ${JSON.stringify(decoded)}`);

    if(decoded.valid) {
        console.log('es256: all tests passed');
    } else {
        console.log('es256: tests failed');
        process.exit(-1);
    }
}
