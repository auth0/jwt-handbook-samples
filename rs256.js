import * as base64 from './base64.js';
import sha256 from './sha256.js';
import { pkcs1v1_5, verifyPkcs1v1_5, hashTypes } from './rsassa.js'; 
import { stringToUtf8, isString, b64, unb64 } from './utils.js';
import * as testkey from './testkey.js';

export default function jwtEncode(header, payload, privateKey) {
    if(typeof header !== 'object' || typeof payload !== 'object') {
        throw new Error('header and payload must be objects');
    }

    header.alg = 'RS256';

    const encHeader = b64(JSON.stringify(header));
    const encPayload = b64(JSON.stringify(payload));
    const jwtUnprotected = `${encHeader}.${encPayload}`;
    const signature = b64(
        pkcs1v1_5.sign(privateKey, 
                       msg => sha256(msg, true), 
                       hashTypes.sha256, stringToUtf8(jwtUnprotected)));

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
    if(header.alg !== 'RS256') {
        throw new Error(`Wrong algorithm: ${header.alg}`);
    }

    const jwtUnprotected = stringToUtf8(`${split[0]}.${split[1]}`);
    const valid = verifyPkcs1v1_5(publicKey, 
                                  msg => sha256(msg, true),
                                  hashTypes.sha256,
                                  jwtUnprotected,
                                  base64.decode(split[2]));

    return {
        header: header,
        payload: JSON.parse(unb64(split[1])),
        valid: valid
    };
}

if(process.env.TEST) {
    const encoded = jwtEncode({}, {sub: "test@test.com"}, testkey.privateKey);
    const decoded = jwtVerifyAndDecode(encoded, testkey.publicKey);
    
    console.log(`Encoded: ${encoded}`);
    console.log(`Decoded: ${JSON.stringify(decoded)}`);

    if(decoded.valid) {
        console.log('rs256: all tests passed');
    } else {
        console.log('rs256: tests failed');
        process.exit(-1);
    }
}
