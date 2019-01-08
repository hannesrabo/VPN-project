package crypto;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static javax.crypto.Cipher.ENCRYPT_MODE;

public class SessionEncrypter {

    private SessionKey sessionKey;
    private Cipher encryptionCipher;

    public SessionEncrypter(int keyLength) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        // Create a new session
        sessionKey = new SessionKey(keyLength);

        // As the target for this platform is java SE, there is no need to manually
        // generate the IV parameter. This is generated automatically when left empty.
        encryptionCipher = Cipher.getInstance("AES/CTR/NoPadding");
        encryptionCipher.init(ENCRYPT_MODE, sessionKey.getSecretKey());
    }

//    public SessionEncrypter(String encodedKey, String encodedIV) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
//        // Create a new session
//        sessionKey = new SessionKey(encodedKey);
//
//        byte[] key = sessionKey.getSecretKey().getEncoded();
//        byte[] iv  = Base64.getDecoder().decode(encodedIV);
//
//        // As the target for this platform is java SE, there is no need to manually
//        // generate the IV parameter. This is generated automatically when left empty.
//        encryptionCipher = Cipher.getInstance("AES/CTR/NoPadding");
//        encryptionCipher.init(
//                ENCRYPT_MODE,
//                new SecretKeySpec(key, "AES"),
//                new IvParameterSpec(iv)
//        );
//    }

    public SessionEncrypter(byte[] rawKey, byte[] rawIV) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        // Create a new session
        sessionKey = new SessionKey(rawKey);

        // As the target for this platform is java SE, there is no need to manually
        // generate the IV parameter. This is generated automatically when left empty.
        encryptionCipher = Cipher.getInstance("AES/CTR/NoPadding");
        encryptionCipher.init(
                ENCRYPT_MODE,
                new SecretKeySpec(rawKey, "AES"),
                new IvParameterSpec(rawIV)
        );
    }

    /**
     * @return The key encoded as a base64 string
     */
//    public String encodeKey() {
//        return sessionKey.encodeKey();
//    }

    public byte[] getRawKey() {
        return sessionKey.getRawKey();
    }

    /**
     * @return The initialization vector for the CTR mode encoded as a base64 string
     */
    public byte[] getRawIV() {
        return encryptionCipher.getIV();
    }

    /**
     * Open a encrypted output stream from the output stream to the cipher output stream.
     * @param outputStream The output stream to send encrypted information over.
     * @return The encrypted output stream.
     */
    public CipherOutputStream openCipherOutputStream(OutputStream outputStream) {
        return new CipherOutputStream(outputStream, encryptionCipher);
    }
}
