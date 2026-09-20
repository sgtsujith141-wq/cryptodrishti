// RSA whose purpose the code does not reveal: a key is generated and handed
// off. Nothing here says whether it will sign or transport keys, so the tool
// must leave the purpose unresolved rather than choose the commoner answer.
package main

import "crypto/rsa"

func newKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(nil, 2048)
}
