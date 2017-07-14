import { isString } from './utils.js';

const table = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 
    'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 
    'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 
    'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 
    'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', 
    '8', '9', '-', '_'
];

/**
 * @param input a Buffer, Uint8Array or Int8Array, Array
 * @returns a String with the encoded values
 */
export function encode(input) {
    let result = "";
    
    for(let i = 0; i < input.length; i += 3) {
        const remaining = input.length - i;

        let concat = input[i] << 16;
        result += (table[concat >>> (24 - 6)]);

        if(remaining > 1) {
            concat |= input[i + 1] << 8;
            result += table[(concat >>> (24 - 12)) & 0x3F];

            if(remaining > 2) {
                concat |= input[i + 2];
                result += table[(concat >>> (24 - 18)) & 0x3F] +
                          table[concat & 0x3F];
            } else {
                result += table[(concat >>> (24 - 18)) & 0x3F] + "=";
            }
        } else {
            result += table[(concat >>> (24 - 12)) & 0x3F] + "==";
        }
    }

    return result;
}

/**
 * @param input a String
 * @returns a Uint8Array with the decoded data
 */
export function decode(input) {
    if(!isString(input)) {
        throw new TypeError("input must be a string");
    }

    let resultLength = Math.trunc(input.length * 6 / 8);
    if(input.endsWith('==')) {
        resultLength -= 2;
    } else if(input.endsWith('=')) {
        --resultLength;
    }
    const result = new Uint8Array(resultLength);
    
    function getVal(i) {
        if(i >= input.length) {
            return 0;
        }

        const char = input[i];
        if(char === '=') {
            return 0;
        }

        // There are faster ways to do this, but this code is educational, so
        // we keep it simple
        const val = table.indexOf(char);
        if(val === -1) {
            throw new Error(`Invalid input: ${input[i]}`);
        }
        return val;
    }

    let i = 0;
    let j = 0;

    // TODO: check bounds for the last group of bytes. JavaScript allows us
    // to skip these checks as out-of-bounds essentially become no-ops.
    for(; j < result.length; i += 4, j += 3) {
        result[j] = getVal(i) << 2;
        result[j] |= getVal(i + 1) >>> 4;
        result[j + 1] = getVal(i + 1) << 4;
        result[j + 1] |= getVal(i + 2) >>> 2;
        result[j + 2] = getVal(i + 2) << 6;
        result[j + 2] |= getVal(i + 3);
    }

    return result;
}

if(process.env.TEST) {
    function genData(length) {
        const result = new Uint8Array(length);
        for(let i = 0; i < result.length; ++i) {
            result[i] = Math.round(Math.random() * 255);
        }
        return result;
    }

    function compare(a, b) {
        if(a.length !== b.length) {
            return false;
        }

        for(let i = 0; i < a.length; ++i) {
            if(a[i] != b[i]) {
                return false;
            }
        }

        return true;
    }

    const data = [];
    for(let i = 0; i < 101; ++i) {
        data.push(genData(i));
    }

    data.forEach(d => {
        const encoded = encode(d);
        const decoded = decode(encoded);
        const decoded2 = decode(encoded.replace(/=/g, ''));

        if(!compare(d, decoded) || !compare(d, decoded2)) {
            console.log(`Test failed for data: ${d} \n\n ` + 
                        `encoded: ${encoded} \n\n ` +
                        `decoded: ${decoded} \n\n`);
            process.exit(-1);
        }
    });

    console.log('base64: all tests passed');
}

