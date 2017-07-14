import { escape, unescape } from 'querystring';
import * as base64 from './base64.js';

export function stringToUtf8(str) {
    if(!isString(str)) {
        throw new TypeError('not a string');
    }    
    const utf8str = unescape(encodeURIComponent(str));
    const result = new Uint8Array(utf8str.length);
    for(let i = 0; i < result.length; ++i) {
        result[i] = utf8str.charCodeAt(i);
    }

    return result;
}

// https://stackoverflow.com/questions/17191945/conversion-between-utf-8-arraybuffer-and-string
export function utf8ToString(uintArray) {
    if(!(uintArray instanceof Uint8Array)) {
        throw new TypeError('not a Uint8Array');
    }

    //Alternative: return Buffer.from(uintArray).toString();

    const encodedString = String.fromCharCode.apply(null, uintArray);
    const decodedString = decodeURIComponent(escape(encodedString));

    return decodedString;
}

export function uint8ArrayAppend(a, b) {
    if(!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) {
        throw new TypeError('expected Uint8Array');
    }

    const result = new Uint8Array(a.length + b.length);
    result.set(a);
    result.set(b, a.length);

    return result;
}

export function uint8ArrayEquals(a, b) {
    if(!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) {
        throw new TypeError('expected Uint8Array');
    }

    if(a.length !== b.length) {
        return false;
    }

    for(let i = 0; i < a.length; ++i) {
        if(a[i] !== b[i]) {
            return false;
        }
    }

    return true;
}

export function isString(value) {
    return (typeof value === 'string') || (value instanceof String);
}

export function b64(data) {
    if(data instanceof Uint8Array) {
        return base64.encode(data).replace(/=/g, ''); 
    } else {
        return base64.encode(stringToUtf8(data)).replace(/=/g, '');
    }
}

export function unb64(data) {
    return utf8ToString(base64.decode(data));
}
