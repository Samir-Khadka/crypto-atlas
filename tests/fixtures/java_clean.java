import java.security.*;
import javax.crypto.*;
import javax.net.ssl.*;

public class JavaClean {
    public void run() throws Exception {
        // strong hash
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        // strong cipher: GCM, not ECB
        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        // SecureRandom, not Random
        SecureRandom sr = new SecureRandom();
        byte[] token = new byte[32];
        sr.nextBytes(token);
        // key from a generator, not a literal
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKeySpec key = new SecretKeySpec(
            kg.generateKey().getEncoded(), "AES");
        // modern TLS
        SSLContext modern = SSLContext.getInstance("TLSv1.3");
        // a verifier that actually checks
        HostnameVerifier hv = (hostname, session) ->
            hostname.equals("example.com");
    }
}
