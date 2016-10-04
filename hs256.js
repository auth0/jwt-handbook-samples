import { encode as base64Encode } from './base64.js';
import sha256 from './sha256.js';
import hmac from './hmac.js'; 
import { stringToUtf8, uint32ArrayToUint8Array } from './utils.js';

function b64(data) {
    if(data instanceof Uint8Array) {
        return base64Encode(data).replace(/=/g, ''); 
    } else {
        return base64Encode(stringToUtf8(data)).replace(/=/g, '');
    }
}

export default function jwtEncode(header, payload, secret) {
    if(typeof header !== 'object' || typeof payload !== 'object') {
        throw new Error('header and payload must be objects');
    }
    if(typeof secret !== 'string') {
        throw new Error("secret must be a string");
    }

    header.alg = 'HS256';

    const encHeader = b64(JSON.stringify(header));
    const encPayload = b64(JSON.stringify(payload));
    const jwtUnprotected = `${encHeader}.${encPayload}`;
    const signature = b64(uint32ArrayToUint8Array(
        hmac(sha256, 512, secret, stringToUtf8(jwtUnprotected), true)));

    return `${jwtUnprotected}.${signature}`;
}

console.log(jwtEncode({}, {sub: "test@test.com"}, 'secret'));
