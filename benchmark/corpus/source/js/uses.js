// Positive cases. Line numbers matter.
const crypto = require("crypto");                                 // 2
crypto.createHash("md5");                                         // 3
crypto.createHash("sha256");                                      // 4
crypto.createHash("sha3-512");                                    // 5
crypto.createHash("blake2b512");                                  // 6
crypto.createCipheriv("aes-256-gcm", k, iv);                      // 7
crypto.generateKeyPairSync("rsa", {});                            // 8
Math.random();                                                    // 9
