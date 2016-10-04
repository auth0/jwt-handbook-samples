import * as assert from 'assert';
import jwt from 'jsonwebtoken';

const payload = {
  sub: "1234567890",
  name: "John Doe",
  admin: true
};

const secret = 'my-secret-key';

const publicRsaKey = `-----BEGIN PUBLIC KEY----- 
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQAB
-----END PUBLIC KEY-----`;

const privateRsaKey = `-----BEGIN RSA PRIVATE KEY----- 
MIICWwIBAAKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQABAoGAD+onAtVye4ic7VR7V50DF9bOnwRwNXrARcDhq9LWNRrRGElESYYTQ6EbatXS3MCyjjX2eMhu/aF5YhXBwkppwxg+EOmXeh+MzL7Zh284OuPbkglAaGhV9bb6/5CpuGb1esyPbYW+Ty2PC0GSZfIXkXs76jXAu9TOBvD0ybc2YlkCQQDywg2R/7t3Q2OE2+yo382CLJdrlSLVROWKwb4tb2PjhY4XAwV8d1vy0RenxTB+K5Mu57uVSTHtrMK0GAtFr833AkEA6avx20OHo61Yela/4k5kQDtjEf1N0LfI+BcWZtxsS3jDM3i1Hp0KSu5rsCPb8acJo5RO26gGVrfAsDcIXKC+bQJAZZ2XIpsitLyPpuiMOvBbzPavd4gY6Z8KWrfYzJoI/Q9FuBo6rKwl4BFoToD7WIUS+hpkagwWiz+6zLoX1dbOZwJACmH5fSSjAkLRi54PKJ8TFUeOP15h9sQzydI8zJU+upvDEKZsZc/UhT/SySDOxQ4G/523Y0sz/OZtSWcol/UMgQJALesy++GdvoIDLfJX5GBQpuFgFenRiRDabxrE9MNUZ2aPFaFp+DyAe+b4nDwuJaW2LURbr8AEZga7oQj0uYxcYw==
-----END RSA PRIVATE KEY-----`;

const publicEcdsaKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEucQ/nQfEgmk5i5czxYtI1TWacrF+
FEXcuIFdf0P6NP3ai7P8r7F40KQn4qqLvAvu7kEAvRRPNVm7nvxxpJdQnQ==
-----END PUBLIC KEY-----`;

const privateEcdsaKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEOnd9s41dBNbV9FLRfmi/5vcTbbgX14aIgpuFxqIMUMoAoGCCqGSM49
AwEHoUQDQgAEucQ/nQfEgmk5i5czxYtI1TWacrF+FEXcuIFdf0P6NP3ai7P8r7F4
0KQn4qqLvAvu7kEAvRRPNVm7nvxxpJdQnQ==
-----END EC PRIVATE KEY-----`;

const signed = {
    hs256: jwt.sign(payload, secret, { 
        algorithm: 'HS256',
        expiresIn: '5s' 
    }),

    rs256: jwt.sign(payload, privateRsaKey, {
        algorithm: 'RS256',
        expiresIn: '5s'
    }),

    es256: jwt.sign(payload, privateEcdsaKey, {
        algorithm: 'ES256',
        expiresIn: '5s'
    }) 
};

const decoded = {
    hs256: jwt.verify(signed.hs256, secret, {
        // Never forget to make this explicit to prevent
        // signature stripping attacks
        algorithms: ['HS256'], 
    }),

    rs256: jwt.verify(signed.rs256, publicRsaKey, {
        // Never forget to make this explicit to prevent
        // signature stripping attacks
        algorithms: ['RS256'], 
    }),

    es256: jwt.verify(signed.es256, publicEcdsaKey, {
        // Never forget to make this explicit to prevent
        // signature stripping attacks
        algorithms: ['ES256'], 
    })
};

console.log(`Decoded: ${JSON.stringify(decoded.hs256)}`);

// Check that the token is invalid after 5 seconds.
setTimeout(() => {
    assert.throws(() => {
        jwt.verify(signed.hs256, secret, {
            algorithms: ['HS256']
        });
    });
    process.exit();
}, 5100);
