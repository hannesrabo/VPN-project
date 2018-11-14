import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class SessionKey {

    private SecretKey secretKey;

    /**
     * Create a new session with a new random secret key.
     * @param keylength The length of the key
     */
    public SessionKey(Integer keylength) throws NoSuchAlgorithmException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(keylength);
        secretKey = generator.generateKey();
    }

    /**
     * Create session from a base 64 encoded string representation of the secret key.
     * @param encodedkey The base 64 encoded string representation of the secret key
     */
    public SessionKey(String encodedkey) {
        byte[] keyBuffer = Base64.getDecoder().decode(encodedkey);
        secretKey = new SecretKeySpec(keyBuffer, "AES");

    }

    /**
     * @return The internal secret key used for the session
     */
    public SecretKey getSecretKey() {
        return secretKey;
    }

    /**
     * Create an encoded key
     * @return The key as a base 64 encoded string.
     */
    public String encodeKey() {
        return Base64
                .getEncoder()
                .withoutPadding()
                .encodeToString(
                        secretKey.getEncoded()
                );
    }

    public static void main(String args[]) {
        try {
            SessionKey key1 = new SessionKey(128);
            System.out.println(key1.encodeKey());
            SessionKey key2 = new SessionKey(key1.encodeKey());
            System.out.println(key2.encodeKey());

            if (key1.getSecretKey().equals(key2.getSecretKey())) {
                System.out.println("Pass");
            }
            else {
                System.out.println("Fail");
            }
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Could not create key for AES");
        }
    }
}
