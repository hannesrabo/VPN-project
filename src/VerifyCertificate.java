import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.*;

import static java.lang.System.exit;



public class VerifyCertificate {

    private static CertificateFactory certificateFactory = null;

    public static X509Certificate readCertificate(String filename) throws IOException, CertificateException {

        if (certificateFactory == null)
            certificateFactory = CertificateFactory.getInstance("X.509");


        try (
            FileInputStream fileInputStream = new FileInputStream(filename);
            BufferedInputStream ca_bufferBufferedInputStream = new BufferedInputStream(fileInputStream);
        ){
            if (ca_bufferBufferedInputStream.available() > 0) {
                X509Certificate tempCert = (X509Certificate) certificateFactory.generateCertificate(ca_bufferBufferedInputStream);
                return tempCert;

            } else
                throw new FileNotFoundException("Could not read stream");

        } catch (Exception e) {
            throw e;
        }
    }

    public static void main(String[] args) {
        if (args.length != 2) {
            System.out.println("Usage: VerifySignature <CA Cert> <User Cert>");
            exit(-1);
        }

        String filename_user_cert       = args[1];
        String filename_ca_cert         = args[0];


        X509Certificate     ca_cert     = null;
        X509Certificate     user_cert   = null;
        try {
            ca_cert     = readCertificate(filename_ca_cert);
            user_cert   = readCertificate(filename_user_cert);

        } catch (IOException e) {
            System.out.println("fail");
            System.out.println("Could not read files");
            exit(-1);
        } catch (CertificateException e) {
            System.out.println("fail");
            System.out.println("Certificate algorithm or file invalid");
            exit(-1);
        }

        System.out.println(ca_cert.getSubjectDN().toString());
        System.out.println(user_cert.getSubjectDN().toString());

        try {
            ca_cert.checkValidity();
            ca_cert.verify(ca_cert.getPublicKey());
            user_cert.checkValidity();
            user_cert.verify(ca_cert.getPublicKey());

            System.out.println("pass\n");

        } catch (CertificateExpiredException e) {
            System.out.println("fail");
            System.out.println("Certificate expired");
        } catch (CertificateNotYetValidException e) {
            System.out.println("fail");
            System.out.println("Certificate not yet valid");
        } catch (CertificateException e) {
            System.out.println("fail");
            System.out.println("Certificate invalid");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("fail");
            System.out.println("Algorithm invalid");
        } catch (InvalidKeyException e) {
            System.out.println("fail");
            System.out.println("Invalid key");
        } catch (SignatureException e) {
            System.out.println("fail");
            System.out.println("Invalid signature");
        } catch (NoSuchProviderException e) {
            System.out.println("fail");
            System.out.println("No provider available");
        }

    }

}
