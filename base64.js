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


