import * as assert from 'assert';

const header = {
    alg: 'none'
};

const payload = {
    sub: "user123",
    session: "ch72gsb320000udocl363eofy",
    name: "Pretty Name",
    lastpage: "/views/settings"
};

// URL-safe variant of Base64
function b64(str) {
    return new Buffer(str).toString('base64')
                          .replace(/=/g, '')
                          .replace(/\+/g, '-')
                          .replace(/\//g, '_');
}

function encode(h, p) {
    const headerEnc = b64(JSON.stringify(h));                    
    const payloadEnc = b64(JSON.stringify(p));
    return `${headerEnc}.${payloadEnc}`;
}

function decode(jwt) {
    const [headerB64, payloadB64] = jwt.split('.');
    // These supports parsing the URL safe variant of Base64 as well.
    const headerStr = new Buffer(headerB64, 'base64').toString();
    const payloadStr = new Buffer(payloadB64, 'base64').toString();
    return {
        header: JSON.parse(headerStr),
        payload: JSON.parse(payloadStr)
    };
}

const encoded = encode(header, payload);
const decoded = decode(encoded);

assert.deepStrictEqual({ 
    header: header, 
    payload: payload 
}, decoded);

console.log(`Encoded: ${encoded}`);
console.log(`Decoded: ${JSON.stringify(decoded)}`);

