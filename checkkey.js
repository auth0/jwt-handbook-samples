var jose = require("node-jose")

var pubkey = "-----BEGIN PUBLIC KEY-----\n" +
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyQDDZ/6a04k6m2nlnPBl" +
"qT8uQxpzFGPFd5ayf+HTRVNdg1C33UNs9yoP7lQKaiAPRHqAyNODPbBo72S29i8F" +
"a+QKPbKDz03bPQ8mkEzvpfNXPRf4CsIhqrUKISvzgfxdei5d+c28bYa9spjB4so+" +
"oMmusNy+INulZaox3AGczSwV0FiQcgzhbq7Eatrh0ewkUxp5vjF73WHXZCx7nWze" +
"sO4GyqHwtC1baERXTR6fn8djwvIuUuJVyvIMJs48HOxehV0Hn4kHXS/5M6Qcnu4F" +
"sJnEndUwCyduGyO1KY699G9Nrwe7d/8xXFqDHaH54aCN7f8/271RVUgEePWiJhpZ" +
"QQIDAQAB\n" +
"-----END PUBLIC KEY-----"

jose.JWK.asKey(pubkey, "pem").then(function(key) {
    jose.JWS.createVerify(key).verify("eyJhbGciOiJQUzI1NiJ9.eyJzdWIiOiJ0ZXN0QHRlc3QuY29tIn0.cnAF_OhYr_3RxVBHYzlvGgGL-hukdftMELUReUuXzm2UwzWNk2zhg7Yg2I0velcGOCSe9eaV-i4g03q972G2HzyZ0vRkXAgEY33TcNhclHue_YUbCmC7ZIn25Ed5Pwo6lr807gJsMcP7mQW7KUJ8utkoaIZMfdAJlRix0xB5QPa-k7077XwQrfAK9y8iI9iJJaJt8twvM4H4N97SYgVIF5JbqG694SEE-Mk5S2qvVMAI4S4fFsrFcWIejKx6HHBLNi4vxPky-j0QOjD-kGFzmOG0Z87GnTX9e8yLPHUGL4eB8xk-gGSSanO6muukSD354KsK_35cTxXft02TUa3TwA").then(function(r) {
        console.log(r);
    }, function(e) {
        console.log(e);
    });
}, function(er) {
    console.log(er);
});

