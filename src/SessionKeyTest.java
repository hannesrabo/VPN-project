import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

class SessionKeyTest {

    @Test
    void createSecretKey() throws NoSuchAlgorithmException {
        SessionKey key1 = new SessionKey(128);
        assertEquals(128, key1.getSecretKey().getEncoded().length * 8);

        SessionKey key2 = new SessionKey(192);
        assertEquals(192, key2.getSecretKey().getEncoded().length * 8);

        SessionKey key3 = new SessionKey(256);
        assertEquals(256, key3.getSecretKey().getEncoded().length * 8);

        System.out.println(key3.encodeKey());

    }

    @org.junit.jupiter.api.Test
    void encodeKey() throws NoSuchAlgorithmException {
        SessionKey key1 = new SessionKey(128);

        assertEquals(key1.getSecretKey().getEncoded().length * 8, 128);

        String keyInput = key1.encodeKey();
        SessionKey key2 = new SessionKey(keyInput);
        assertEquals(key1.getSecretKey().getEncoded().length * 8, 128);

        assertTrue(key1.getSecretKey().equals(key2.getSecretKey()));
    }
}