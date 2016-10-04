import jose from 'node-jose';

const payload = {
    sub: 'test-subject',
    secret: 'nobody should read this!'
};

// Create an empty keystore
const keystore = jose.JWK.createKeyStore();

// Generate a few keys. You may also import keys generated from external
// sources.
const promises = [
    keystore.generate('oct', 128, { kid: 'example-1' }),
    keystore.generate('RSA', 2048, { kid: 'example-2' }),
    keystore.generate('EC', 'P-256', { kid: 'example-3' }),    
];

function encrypt(key, options, plaintext) {
    return jose.JWE.createEncrypt(options, key)
                   .update(plaintext)
                   .final();
}

function a128gcm(compact) {
    const key = keystore.get('example-1');
    const options = {  
        format: compact ? 'compact' : 'general',
        contentAlg: 'A128GCM'
    };

    return encrypt(key, options, JSON.stringify(payload));
}

function rsa(compact) {
    const key = keystore.get('example-2');
    const options = {  
        format: compact ? 'compact' : 'general',
        contentAlg: 'A128CBC-HS256'
    };

    return encrypt(key, options, JSON.stringify(payload));
}

function ecdhes(compact) {
    const key = keystore.get('example-3');
    const options = {  
        format: compact ? 'compact' : 'general',
        contentAlg: 'A128GCM'
    };

    return encrypt(key, options, JSON.stringify(payload));
}

function nested(compact) {
    const signingKey = keystore.get('example-3');
    const encryptionKey = keystore.get('example-2');

    const signingPromise = jose.JWS.createSign(signingKey)
                                   .update(JSON.stringify(payload))
                                   .final();

    const promise = new Promise((resolve, reject) => {
    
        signingPromise.then(result => {
            const options = {  
                format: compact ? 'compact' : 'general',
                contentAlg: 'A128CBC-HS256'
            };
            resolve(encrypt(encryptionKey, options, JSON.stringify(result)));
        }, error => {
            reject(error);
        });

    });

    return promise;
}

function resultPrinter(name, promise) {
    function p(text) {
        console.log(`${name}: ${JSON.stringify(text, null, '\t')}\n`);
    }
    promise.then(p, p);
}

Promise.all(promises).then(keys => {

    resultPrinter('AES128KW + AES128GCM as JSON', a128gcm(false));
    resultPrinter('AES128KW + AES128GCM as Compact JWT', a128gcm(true));
    
    resultPrinter('RSAES-OAEP + AES128CBC + HS256 as JSON', rsa(false));
    resultPrinter('RSAES-OAEP + AES128CBC + HS256 as Compact JWT', rsa(true));
    
    resultPrinter('ECDH-ES P-256 + AES128GCM as JSON', ecdhes(false));
    resultPrinter('ECDH-ES P-256 + AES128GCM as Compact JWT', ecdhes(true));
    
    resultPrinter('Nested JWT as JSON', nested(false));
    resultPrinter('Nested JWT as Compact JWT', nested(true));

    // Decryption test
    a128gcm(true).then(result => {
        jose.JWE.createDecrypt(keystore.get('example-1'))
                .decrypt(result)
                .then(decrypted => {
                    decrypted.payload = JSON.parse(decrypted.payload);
                    console.log(`Decrypted result: ${JSON.stringify(decrypted)}`);
                }, error => {
                    console.log(error);
                });
    }, error => {
        console.log(error);
    });

}, error => {
    console.log(error);
});



