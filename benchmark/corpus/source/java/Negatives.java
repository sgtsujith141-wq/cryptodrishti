// Negative cases. Nothing here is a cryptographic call site.
public class Negatives {                                          // 2
    // Cipher.getInstance("AES/ECB/PKCS5Padding") is what we used to do.  // 3
    /* MessageDigest.getInstance("MD5") was removed in release 4.2. */    // 4
    private static final String DOC = "Use SHA-256, never MD5.";  // 5
    private String rsaVendorName = "ExampleCorp";                 // 6
    private int aesColumnWidth = 256;                             // 7
    void notCrypto() {                                            // 8
        System.out.println("ECDH is discussed in the appendix");  // 9
    }                                                             // 10
}                                                                 // 11
