package vpn.crypto.test;

import vpn.crypto.SessionKey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;

class SessionKeyTest {

    @Test
    void createSecretKey() throws NoSuchAlgorithmException {
        SessionKey key1 = new SessionKey(128);
        Assertions.assertEquals(128, key1.getSecretKey().getEncoded().length * 8);

        SessionKey key2 = new SessionKey(192);
        Assertions.assertEquals(192, key2.getSecretKey().getEncoded().length * 8);

        SessionKey key3 = new SessionKey(256);
        Assertions.assertEquals(256, key3.getSecretKey().getEncoded().length * 8);

    }

    @Test
    void simpleKeyQualityTest() throws NoSuchAlgorithmException {
        SessionKey sk1 = new SessionKey(128);
        SessionKey sk2 = new SessionKey(128);

        Assertions.assertFalse(sk1.encodeKey().equals(sk2.encodeKey()));
    }

    @Test
    void encodeKey() throws NoSuchAlgorithmException {
        SessionKey key1 = new SessionKey(128);

        Assertions.assertEquals(key1.getSecretKey().getEncoded().length * 8, 128);

        String keyInput = key1.encodeKey();
        SessionKey key2 = new SessionKey(keyInput);
        Assertions.assertEquals(key1.getSecretKey().getEncoded().length * 8, 128);

        Assertions.assertTrue(key1.getSecretKey().equals(key2.getSecretKey()));
    }
}
