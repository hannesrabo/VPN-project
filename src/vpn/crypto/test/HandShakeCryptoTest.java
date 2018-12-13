package vpn.crypto.test;

import vpn.crypto.HandShakeCrypto;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

class HandShakeCryptoTest {

    @Test
    void decrypt() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, CertificateException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {

        PrivateKey privateKey = HandShakeCrypto.getPrivateKeyFromKeyFile("cert/user_key.pem");
        PublicKey publicKey = HandShakeCrypto.getPublicKeyFromCertFile("cert/user_cert.pem");

        byte[] plaintext = "hello this is a string".getBytes();
        byte[] ciphertext = HandShakeCrypto.encrypt(plaintext, publicKey);

        Assertions.assertNotEquals(ciphertext, plaintext);

        byte[] decryptedText = HandShakeCrypto.decrypt(ciphertext, privateKey);

        Assertions.assertEquals(new String(plaintext), new String(decryptedText));
    }

    @Test
    void encodeAndDecode() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, CertificateException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {

        PrivateKey privateKey = HandShakeCrypto.getPrivateKeyFromKeyFile("cert/user_key.pem");
        PublicKey publicKey = HandShakeCrypto.getPublicKeyFromCertFile("cert/user_cert.pem");

        byte[] plaintext = "hello this is a string".getBytes();
        byte[] ciphertext = HandShakeCrypto.encrypt(plaintext, publicKey);

        byte[] ciphertext2 = HandShakeCrypto.encrypt(plaintext, publicKey);

//        Assertions.assertEquals(new String(ciphertext), new String(ciphertext2));

        String transport = HandShakeCrypto.encodeByteArray(ciphertext);
        byte[] ciperTextOnTheOtherSide = HandShakeCrypto.decodeString(transport);

        byte[] decryptedText = HandShakeCrypto.decrypt(ciperTextOnTheOtherSide, privateKey);

        byte[] decryptedText2 = HandShakeCrypto.decrypt(ciphertext2, privateKey);


        Assertions.assertEquals(new String(plaintext), new String(decryptedText));
        Assertions.assertEquals(new String(plaintext), new String(decryptedText2));
    }

    @Test
    void getPublicKeyFromCertFile() throws IOException, CertificateException {
        PublicKey myKey = HandShakeCrypto.getPublicKeyFromCertFile("cert/user_cert.pem");

        Assertions.assertTrue(myKey.getEncoded().length > 0);
    }

    @Test
    void getPrivateKeyFromKeyFile() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        PrivateKey myKey = HandShakeCrypto.getPrivateKeyFromKeyFile("cert/user_key.pem");

        Assertions.assertTrue(myKey.getEncoded().length > 0);
    }
}