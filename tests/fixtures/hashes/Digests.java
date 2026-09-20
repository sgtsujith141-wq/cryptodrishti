// Ground truth for hash identity in the JCE, where the algorithm is a string.
public class Digests {
    void run() throws Exception {
        MessageDigest.getInstance("MD5");
        MessageDigest.getInstance("SHA-1");
        MessageDigest.getInstance("SHA-256");
        MessageDigest.getInstance("SHA-384");
        MessageDigest.getInstance("SHA-512");
        MessageDigest.getInstance("SHA3-224");
        MessageDigest.getInstance("SHA3-256");
        MessageDigest.getInstance("SHA3-384");
        MessageDigest.getInstance("SHA3-512");
    }
}
