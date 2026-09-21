/* Positive cases. Line numbers matter. */
#include <openssl/evp.h>                                          /* 2 */
void f(void) {                                                    /* 3 */
    EVP_aes_256_gcm();                                            /* 4 */
    EVP_aes_128_cbc();                                            /* 5 */
    RSA_sign(0, 0, 0, 0, 0, 0);                                   /* 6 */
    RSA_public_encrypt(0, 0, 0, 0, 0);                            /* 7 */
    RSA_generate_key_ex(0, 2048, 0, 0);                           /* 8 */
    ECDH_compute_key(0, 0, 0, 0, 0);                              /* 9 */
    MD5_Init(0);                                                  /* 10 */
    EVP_sha3_512();                                               /* 11 */
}                                                                 /* 12 */
