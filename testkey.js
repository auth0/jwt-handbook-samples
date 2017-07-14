import bigInt from 'big-integer';

export const privateKey = { 
    size: 2048
};

// You can get these numbers with:
// openssl rsa -inform PEM -text -noout < testkey.pem

privateKey.n = bigInt('00c900c367fe9ad3893a9b69e59cf0' +
                    '65a93f2e431a731463c57796b27fe1' +
                    'd345535d8350b7dd436cf72a0fee54' +
                    '0a6a200f447a80c8d3833db068ef64' +
                    'b6f62f056be40a3db283cf4ddb3d0f' +
                    '26904cefa5f3573d17f80ac221aab5' +
                    '0a212bf381fc5d7a2e5df9cdbc6d86' +
                    'bdb298c1e2ca3ea0c9aeb0dcbe20db' +
                    'a565aa31dc019ccd2c15d05890720c' +
                    'e16eaec46adae1d1ec24531a79be31' +
                    '7bdd61d7642c7b9d6cdeb0ee06caa1' +
                    'f0b42d5b6844574d1e9f9fc763c2f2' +
                    '2e52e255caf20c26ce3c1cec5e855d' +
                    '079f89075d2ff933a41c9eee05b099' +
                    'c49dd5300b276e1b23b5298ebdf46f' +
                    '4daf07bb77ff315c5a831da1f9e1a0' +
                    '8dedff3fdbbd5155480478f5a2261a' +
                    '5941', 16);

privateKey.d = bigInt('1dc96f2bca1f4799de85897bed75f2' +
                    '9ad23218dfa28e32fae06e04a5cee1' +
                    '70349a770b4f340af9eae6e0d580be' +
                    'ca5b55e7dfff95c3427fb1d4db2521' +
                    'b7f9dfe3cd37774d2d1b5b7e51de1c' +
                    'e8e57dde29e193bc2995ee8eeead45' +
                    '8304f06122f4f75647b6ed362f44f8' +
                    '77af0b8c804c27a7bbab9a0ad2f3b9' +
                    'df0709bc80c0abe6c90518999a19d0' +
                    'c0910a7fb46cd3a2c77c1fea297cc5' +
                    'c91640bde500322f225abf22baf69e' +
                    '45c0e53286f323381cd9bf8ef3837a' +
                    '2cc5c944778880834d081bcd01d9f2' +
                    '456c3a4a7e51a4acb2c3c0908b8755' +
                    '93117258f012f63e5cb25b84944940' +
                    'ef413dd29022f090ff93457638ebf9' +
                    '1e3658fe91fcb2f4b489d8981ce732' +
                    'c1', 16);

// You can get these numbers with:
// openssl rsa -pubin -inform PEM -text -noout < pubtestkey.pem

export const publicKey = {
    size: privateKey.size,
    n: privateKey.n,
    e: bigInt(0x10001)
};

