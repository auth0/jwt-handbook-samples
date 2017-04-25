import { unescape } from 'querystring';

export function stringToUtf8(str) {
    if(typeof str !== 'string') {
        throw new Error('not a string');
    }    
    const utf8str = unescape(encodeURIComponent(str));
    const result = new Uint8Array(utf8str.length);
    for(let i = 0; i < result.length; ++i) {
        result[i] = utf8str.charCodeAt(i);
    }

    return result;
}

export function uint8ArrayAppend(a, b) {
    if(!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) {
        throw new Error('expected Uint8Array');
    }

    const result = new Uint8Array(a.length + b.length);
    result.set(a);
    result.set(b, a.length);

    return result;
}
