// RSA used only for key transport. Must be recommended a KEM or a hybrid.
package main

import "crypto/rsa"

func wrap(pub *rsa.PublicKey, sessionKey []byte) ([]byte, error) {
	return rsa.EncryptOAEP(nil, nil, pub, sessionKey, nil)
}

func unwrap(priv *rsa.PrivateKey, blob []byte) ([]byte, error) {
	return rsa.DecryptOAEP(nil, nil, priv, blob, nil)
}
