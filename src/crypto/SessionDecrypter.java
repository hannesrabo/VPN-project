package crypto;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static javax.crypto.Cipher.DECRYPT_MODE;

public class SessionDecrypter {

//    private SessionKey sessionKey;
    private Cipher decryptionCipher;

//    /**
//     * Create a new session encrypter with parameters.
//     * @param encodedKey The key to use for encrypting the stream.
//     * @param iv The initialization vector for the CTR mode.
//     */
//    public SessionDecrypter(String encodedKey, byte[] iv)
//            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException
//    {
//        sessionKey = new SessionKey(encodedKey);
//
//        byte[] key = sessionKey.getSecretKey().getEncoded();
//
//        decryptionCipher = Cipher.getInstance("AES/CTR/NoPadding");
//        decryptionCipher.init(
//                DECRYPT_MODE,
//                new SecretKeySpec(key, "AES"),
//                new IvParameterSpec(iv)
//            );
//    }

    public SessionDecrypter(byte[] rawKey, byte[] rawIV)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException
    {
        decryptionCipher = Cipher.getInstance("AES/CTR/NoPadding");
        decryptionCipher.init(
                DECRYPT_MODE,
                new SecretKeySpec(rawKey, "AES"),
                new IvParameterSpec(rawIV)
        );
    }

    /**
     * @param inputStream The encrypted input stream to read from.
     * @return A cipher input stream that the user can read plaintext data from.
     */
    public CipherInputStream openCipherInputStream(InputStream inputStream) {
        return new CipherInputStream(inputStream, decryptionCipher);
    }
}
