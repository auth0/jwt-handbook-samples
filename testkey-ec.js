import bigInt from 'big-integer';
import { getPublicKey } from './ecdsa.js';

export const privateKey = {
    d: bigInt('7af6732f581d005afcf216f6385ff6' +
              '371029242cc60840dd7d2a7a5503b7' +
              'd21c', 16)
};

export const publicKey = {};
publicKey.Q = getPublicKey(privateKey);
