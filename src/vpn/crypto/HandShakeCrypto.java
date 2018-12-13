package vpn.crypto;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import static javax.crypto.Cipher.DECRYPT_MODE;

public class HandShakeCrypto {

    public static String encodeByteArray(byte[] bytes) {
        return Base64.getEncoder().withoutPadding().encodeToString(bytes);
    }

    public static byte[] decodeString(String encodedString) {
        return Base64.getDecoder().decode(encodedString);
    }

    /**
     * Encrypt a byte buffer with plaintext
     * @param plaintext The buffer containing text to encrypt
     * @param key The public key to encrypt with
     * @return A new byte buffer containing cipther text
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidKeyException
     */
    public static byte[] encrypt(byte[] plaintext, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        return cipher.doFinal(plaintext);
    }

    /**
     * Decrypt a message
     * @param ciphertext The byte buffer containing the cipther text to decrypt
     * @param key The private key to use
     * @return A new byte buffer containing plain text
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static byte[] decrypt(byte[] ciphertext, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(DECRYPT_MODE, key);

        return cipher.doFinal(ciphertext);
    }

    /**
     * Extract the public key from a certificate file
     * @param certfilename The filename of the certificate to read.
     * @return The public key
     * @throws IOException When the file is inaccessible
     * @throws CertificateException If the certificate file is invalid
     */
    public static PublicKey getPublicKeyFromCertFile(String certfilename) throws IOException, CertificateException {
        return VerifyCertificate
                .readCertificate(certfilename)
                .getPublicKey();
    }

    /**
     * Create a private key from a text base .pem file encoded with PKCS#1
     * @param keyfilename The filename of the file to read
     * @return The private key
     * @throws IOException When file does not exist or can not be read
     * @throws NoSuchAlgorithmException When the decoder does not exist
     * @throws InvalidKeySpecException If the file has an invalid format
     */
    public static PrivateKey getPrivateKeyFromKeyFile(String keyfilename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        byte[] rawBytes;

        // Decode the text based file format
        try ( BufferedReader reader = new BufferedReader(new FileReader(keyfilename))) {
            StringBuilder sb = new StringBuilder();
            String currentLine;

            // Read all lines except those that are for start and end.
            while ((currentLine = reader.readLine()) != null) {
                if ( !currentLine.startsWith("-----")) {
                    sb.append(currentLine);
                }
            }

            rawBytes = Base64.getDecoder().decode(sb.toString());
        }

        // Create the key from the byte buffer
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(
                new PKCS8EncodedKeySpec(rawBytes)
        );
    }

}
