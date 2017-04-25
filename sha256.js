const k = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
           0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
           0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
           0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
           0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
           0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
           0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
           0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
           0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
           0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
           0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
           0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
           0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
           0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
           0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
           0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];

function padMessage(message) {
    if(!(message instanceof Uint8Array) && !(message instanceof Int8Array)) {
        throw new Error("unsupported message container");
    }

    const bitLength = message.length * 8;
    const fullLength = bitLength + 65; //Extra 1 + message size.
    let paddedLength = (fullLength + (512 - fullLength % 512)) / 32;
    let padded = new Uint32Array(paddedLength);

    for(let i = 0; i < message.length; ++i) {
        padded[Math.floor(i / 4)] |= (message[i] << (24 - (i % 4) * 8));
    }
    
    padded[Math.floor(message.length / 4)] |= (0x80 << (24 - (message.length % 4) * 8));
    // TODO: support messages with bitLength longer than 2^32
    padded[padded.length - 1] = bitLength;

    return padded;
}

function rotr(x, n) {
    return (x >>> n) | (x << (32 - n));
}

function rotl(x, n) {
    return (x << n) | (x >>> (32 - n));
}

function ch(x, y, z) {
    return (x & y) ^ ((~x) & z);
}

function maj(x, y, z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

function bsig0(x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

function bsig1(x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

function ssig0(x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3);
}

function ssig1(x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >>> 10);
}

export default function sha256(message, returnBytes) {
    // Initial hash values
    const h_ = Uint32Array.of(
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19
    );

    const padded = padMessage(message);
    const w = new Uint32Array(64);    
    for(let i = 0; i < padded.length; i += 16) { 
        for(let t = 0; t < 16; ++t) {
            w[t] = padded[i + t];
        }
        for(let t = 16; t < 64; ++t) {
            w[t] = ssig1(w[t - 2]) + w[t - 7] + ssig0(w[t - 15]) + w[t - 16];
        }

        let a = h_[0] >>> 0;
        let b = h_[1] >>> 0;
        let c = h_[2] >>> 0;
        let d = h_[3] >>> 0;
        let e = h_[4] >>> 0;
        let f = h_[5] >>> 0;
        let g = h_[6] >>> 0;
        let h = h_[7] >>> 0;
        
        for(let t = 0; t < 64; ++t) {
            let t1 = h + bsig1(e) + ch(e, f, g) + k[t] + w[t];
            let t2 = bsig0(a) + maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;            
        }

        h_[0] = (a + h_[0]) >>> 0;
        h_[1] = (b + h_[1]) >>> 0;
        h_[2] = (c + h_[2]) >>> 0;
        h_[3] = (d + h_[3]) >>> 0;
        h_[4] = (e + h_[4]) >>> 0;
        h_[5] = (f + h_[5]) >>> 0;
        h_[6] = (g + h_[6]) >>> 0;
        h_[7] = (h + h_[7]) >>> 0;
    }

    if(returnBytes) {
        const result = new Uint8Array(h_.length * 4);
        h_.forEach((value, index) => {
            const i = index * 4;
            result[i    ] = (value >>> 24) & 0xFF;
            result[i + 1] = (value >>> 16) & 0xFF;
            result[i + 2] = (value >>> 8)  & 0xFF;
            result[i + 3] = (value >>> 0)  & 0xFF;
        });

        return result;
    } else {
        function toHex(n) {
            let str = (n >>> 0).toString(16);
            let result = "";
            for(let i = str.length; i < 8; ++i) {
                result += "0";
            }
            return result + str;
        }
        let result = "";
        h_.forEach(n => {
            result += toHex(n);
        });
        return result;
    }
}

sha256.byteLength = 256 / 8;

if(process.env.TEST) {
    const test = 'abc';
    const testArray = new Uint8Array(test.length);
    for(let i = 0; i < testArray.length; ++i) {
        testArray[i] = test.charCodeAt(i);
    }
    console.log(sha256(testArray));
}
