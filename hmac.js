import sha256 from './sha256.js';
import {
    uint8ArrayAppend as append, 
    stringToUtf8 
} from './utils.js';

export default function hmac(hashFn, blockSizeBits, secret, message, returnBytes) {
    if(!(message instanceof Uint8Array)) {
        throw new Error('message must be of Uint8Array');
    }

    const blockSizeBytes = blockSizeBits / 8;

    const ipad = new Uint8Array(blockSizeBytes);
    const opad = new Uint8Array(blockSizeBytes);    
    ipad.fill(0x36);
    opad.fill(0x5c);

    const secretBytes = stringToUtf8(secret);
    let paddedSecret;
    if(secretBytes.length <= blockSizeBytes) {
        const diff = blockSizeBytes - secretBytes.length;
        paddedSecret = new Uint8Array(blockSizeBytes);
        paddedSecret.set(secretBytes);
    } else {
        paddedSecret = hashFn(secretBytes);
    }

    const ipadSecret = ipad.map((value, index) => {
        return value ^ paddedSecret[index];
    });
    const opadSecret = opad.map((value, index) => {
        return value ^ paddedSecret[index];
    });

    // HMAC(message) = H(K' XOR opad || H(K' XOR ipad || message))
    const result = hashFn(
        append(opadSecret, hashFn(append(ipadSecret, message), true)), 
        returnBytes);

    return result;
}

if(process.env.TEST) {
    console.log(sha256(stringToUtf8('abc')));
    console.log(hmac(sha256, 512, 'test', stringToUtf8('abc')));
}
