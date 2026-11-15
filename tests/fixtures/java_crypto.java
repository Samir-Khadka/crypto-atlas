import java.security.*;
import java.util.Random;
import javax.crypto.*;
import javax.net.ssl.*;

public class JavaCrypto {
    public void run() throws Exception {
        // weak hash
        MessageDigest md = MessageDigest.getInstance("MD5");
        // weak cipher: ECB mode
        Cipher ecb = Cipher.getInstance("AES/ECB/PKCS5Padding");
        // weak cipher: DES by name
        Cipher des = Cipher.getInstance("DES");
        // RSA keygen, too small
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(1024);
        // EC keygen, weak curve
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        ec.initialize(new ECGenParameterSpec("secp192r1"));
        // weak random: Random assigned to a secret-named variable
        Random keyGen = new Random();
        // weak random: Random output into a secret-named array
        Random rnd = new Random();
        byte[] keyBytes = new byte[16];
        rnd.nextBytes(keyBytes);
        // hardcoded key
        SecretKeySpec key = new SecretKeySpec(
            "hardcoded-secret".getBytes(), "AES");
        // old TLS
        SSLContext old = SSLContext.getInstance("TLSv1");
        // trust-all hostname verifier (lambda)
        HostnameVerifier hv = (hostname, session) -> true;
        // trust-all certificate check (empty method)
        X509TrustManager trustAll = new X509TrustManager() {
            public void checkClientTrusted(
                java.security.cert.X509Certificate[] c, String a) {}
            public void checkServerTrusted(
                java.security.cert.X509Certificate[] c, String a) {}
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return null;
            }
        };
        // post-quantum, already migrated
        KeyPairGenerator pq = KeyPairGenerator.getInstance("ML-KEM");
    }
}
