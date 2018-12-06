import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import static org.junit.jupiter.api.Assertions.*;

class HandShakeCryptoTest {

    @Test
    void decrypt() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, CertificateException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {

        PrivateKey privateKey = HandShakeCrypto.getPrivateKeyFromKeyFile("user_key.pem");
        PublicKey publicKey = HandShakeCrypto.getPublicKeyFromCertFile("user.pem");

        byte[] plaintext = "hello this is a string".getBytes();
        byte[] ciphertext = HandShakeCrypto.encrypt(plaintext, publicKey);

        Assertions.assertNotEquals(ciphertext, plaintext);

        byte[] decryptedText = HandShakeCrypto.decrypt(ciphertext, privateKey);

        Assertions.assertEquals(new String(plaintext), new String(decryptedText));
    }

    @Test
    void getPublicKeyFromCertFile() throws IOException, CertificateException {
        PublicKey myKey = HandShakeCrypto.getPublicKeyFromCertFile("user.pem");

        Assertions.assertTrue(myKey.getEncoded().length > 0);
    }

    @Test
    void getPrivateKeyFromKeyFile() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        PrivateKey myKey = HandShakeCrypto.getPrivateKeyFromKeyFile("user_key.pem");

        Assertions.assertTrue(myKey.getEncoded().length > 0);
    }
}