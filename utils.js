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

export function uint32ArrayToUint8Array(uint32array) {
    if(!(uint32array instanceof Uint32Array)) {
        throw new Error("Uint32Array needed");
    }

    const result = new Uint8Array(uint32array.length * 4);
    uint32array.forEach((value, index) => {
        const i = index * 4;
        result[i    ] = (value >>> 24) & 0xFF;
        result[i + 1] = (value >>> 16) & 0xFF;
        result[i + 2] = (value >>> 8)  & 0xFF;
        result[i + 3] = (value >>> 0)  & 0xFF;
    });

    return result;
}
