package crypto.test;

import crypto.SessionDecrypter;
import crypto.SessionEncrypter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.*;
import javax.crypto.*;

public class SessionCryptoTest  {
    static String PLAININPUT = "test_data/plaininput";
    static String PLAINOUTPUT = "test_data/plainoutput";
    static String CIPHER = "test_data/cipher";
    static Integer KEYLENGTH = 128;

    @Test
    public void testCrypto() throws Exception {
        int b;

        // Create encrypter instance for a given key length
        SessionEncrypter sessionencrypter = new SessionEncrypter(KEYLENGTH);

        Assertions.assertNotEquals(new String((new SessionEncrypter(KEYLENGTH)).getRawIV()), new String((new SessionEncrypter(KEYLENGTH)).getRawIV()));

        // Attach output file to encrypter, and open input file
        try (
                CipherOutputStream cryptoout = sessionencrypter.openCipherOutputStream(new FileOutputStream(CIPHER));
                FileInputStream plainin = new FileInputStream(PLAININPUT);
        ) {

            // Copy data byte by byte from plain input to crypto output via encrypter

            while ((b = plainin.read()) != -1) {
                cryptoout.write(b);
            }
        }

        // Now ciphertext is in cipher output file. Decrypt it back to plaintext.

        // Create decrypter instance using cipher parameters from encrypter  
        SessionDecrypter sessiondecrypter = new SessionDecrypter(sessionencrypter.getRawKey(), sessionencrypter.getRawIV());

        // Attach input file to decrypter, and open output file
        try (
                CipherInputStream cryptoin = sessiondecrypter.openCipherInputStream(new FileInputStream(CIPHER));
                FileOutputStream plainout = new FileOutputStream(PLAINOUTPUT);
        ) {
            // Copy data byte by byte from cipher input to plain output via decrypter
            while ((b = cryptoin.read()) != -1) {
                plainout.write(b);
            }
        }

        char[] inputBuffer  = new char[400];
        char[] outputBuffer = new char[400];

        try (
            FileReader f1 = new FileReader(PLAININPUT);
            FileReader f2 = new FileReader(PLAINOUTPUT)
        ) {
            f1.read(inputBuffer);
            f2.read(outputBuffer);
        }

        Assertions.assertArrayEquals(outputBuffer, inputBuffer);
    }
}