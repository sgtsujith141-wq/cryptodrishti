// RSA used only for signatures. Must be recommended a signature scheme.
package main

import "crypto/rsa"

func sign(k *rsa.PrivateKey, digest []byte) ([]byte, error) {
	return rsa.SignPSS(nil, k, 0, digest, nil)
}

func verify(k *rsa.PublicKey, digest, sig []byte) error {
	return rsa.VerifyPKCS1v15(k, 0, digest, sig)
}
