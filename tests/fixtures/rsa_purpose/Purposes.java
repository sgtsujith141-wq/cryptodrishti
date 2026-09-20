// The same three cases through the JCE, where the API itself is the signal.
public class Purposes {
    // Signature.getInstance is unambiguously signing.
    void signing() throws Exception { Signature.getInstance("SHA256withRSA"); }

    // Cipher.getInstance with an asymmetric algorithm is key transport.
    void transport() throws Exception { Cipher.getInstance("RSA/ECB/OAEPPadding"); }

    // Generating a key pair settles nothing about its use.
    void ambiguous() throws Exception { KeyPairGenerator.getInstance("RSA"); }
}
