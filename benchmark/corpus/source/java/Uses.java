// Positive cases. Line numbers matter — the manifest refers to them.
public class Uses {                                               // 2
    void ciphers() throws Exception {                             // 3
        Cipher.getInstance("AES/GCM/NoPadding");                  // 4
        Cipher.getInstance("AES/ECB/PKCS5Padding");               // 5
        Cipher.getInstance("DESede/CBC/PKCS5Padding");            // 6
        Cipher.getInstance("RSA/ECB/OAEPPadding");                // 7
    }                                                             // 8
    void digests() throws Exception {                             // 9
        MessageDigest.getInstance("MD5");                         // 10
        MessageDigest.getInstance("SHA-256");                     // 11
        MessageDigest.getInstance("SHA3-512");                    // 12
    }                                                             // 13
    void signatures() throws Exception {                          // 14
        Signature.getInstance("SHA256withRSA");                   // 15
        Signature.getInstance("SHA256withECDSA");                 // 16
    }                                                             // 17
    void agreement() throws Exception {                           // 18
        KeyAgreement.getInstance("ECDH");                         // 19
    }                                                             // 20
    void generation() throws Exception {                          // 21
        KeyPairGenerator.getInstance("RSA");                      // 22
    }                                                             // 23
    void mac() throws Exception {                                 // 24
        Mac.getInstance("HmacSHA256");                            // 25
    }                                                             // 26
    void random() {                                               // 27
        new java.util.Random();                                   // 28
    }                                                             // 29
}                                                                 // 30
