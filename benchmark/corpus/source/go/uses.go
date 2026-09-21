// Positive cases. Line numbers matter.
package corpus                                                    // 2
                                                                  // 3
import (                                                          // 4
	"crypto/rsa"                                              // 5
	"crypto/ecdsa"                                            // 6
	"crypto/ed25519"                                          // 7
	"crypto/md5"                                              // 8
)                                                                 // 9
                                                                  // 10
func sign(k *rsa.PrivateKey, d []byte) { rsa.SignPSS(nil, k, 0, d, nil) }      // 11
func wrap(k *rsa.PublicKey, d []byte)  { rsa.EncryptOAEP(nil, nil, k, d, nil) } // 12
func gen()                             { rsa.GenerateKey(nil, 2048) }          // 13
func ec(k *ecdsa.PrivateKey, d []byte) { ecdsa.SignASN1(nil, k, d) }            // 14
func ed(k ed25519.PrivateKey, d []byte) { ed25519.Sign(k, d) }                  // 15
func weak(d []byte)                    { md5.Sum(d) }                           // 16
