// Ground truth for hash identity in Node, where the algorithm is a string.
const crypto = require("crypto");
crypto.createHash("md5");
crypto.createHash("sha1");
crypto.createHash("sha256");
crypto.createHash("sha384");
crypto.createHash("sha512");
crypto.createHash("sha3-256");
crypto.createHash("sha3-512");
crypto.createHash("blake2b512");
crypto.createHash("blake2s256");
