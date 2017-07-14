import sha256 from './sha256.js';
import hmac from './hmac.js'; 
import { stringToUtf8, isString, b64, unb64 } from './utils.js';

export default function jwtEncode(header, payload, secret) {
    if(typeof header !== 'object' || typeof payload !== 'object') {
        throw new TypeError('header and payload must be objects');
    }
    if(!isString(secret)) {
        throw new TypeError("secret must be a string");
    }

    header.alg = 'HS256';

    const encHeader = b64(JSON.stringify(header));
    const encPayload = b64(JSON.stringify(payload));
    const jwtUnprotected = `${encHeader}.${encPayload}`;
    const signature = 
        b64(hmac(sha256, 512, secret, stringToUtf8(jwtUnprotected), true));

    return `${jwtUnprotected}.${signature}`;
}

export function jwtVerifyAndDecode(jwt, secret) {
    if(!isString(jwt) || !isString(secret)) {
        throw new TypeError('jwt and secret must be strings');
    }

    const split = jwt.split('.');
    if(split.length !== 3) {
        throw new Error('Invalid JWT format');
    }

    const header = JSON.parse(unb64(split[0]));
    if(header.alg !== 'HS256') {
        throw new Error(`Wrong algorithm: ${header.alg}`);
    }

    const jwtUnprotected = `${split[0]}.${split[1]}`;
    const signature = 
        b64(hmac(sha256, 512, secret, stringToUtf8(jwtUnprotected), true));

    return {
        header: header,
        payload: JSON.parse(unb64(split[1])),
        valid: signature == split[2]
    };
}

if(process.env.TEST) {
    const secret = 'secret';
    const encoded = jwtEncode({}, {sub: "test@test.com"}, secret);
    const decoded = jwtVerifyAndDecode(encoded, secret);
    
    console.log(`Encoded: ${encoded}`);
    console.log(`Decoded: ${JSON.stringify(decoded)}`);

    if(!decoded.valid) {
        console.log('hs256: test failed');
        process.exit(-1);
    } else {
        console.log('hs256: all tests passed');
    }
}

