package vpn.crypto;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.Base64;

import static java.lang.System.exit;



public class VerifyCertificate {

    private static CertificateFactory certificateFactory = null;

    private static X509Certificate createCertificate(InputStream inputStream) throws CertificateException {

        if (certificateFactory == null)
            certificateFactory = CertificateFactory.getInstance("X.509");

        return (X509Certificate) certificateFactory.generateCertificate(inputStream);
    }

    public static X509Certificate readCertificate(String filename) throws IOException, CertificateException {
        try (
            FileInputStream fileInputStream = new FileInputStream(filename);
            BufferedInputStream certBInputStream = new BufferedInputStream(fileInputStream);
        ){
            if (certBInputStream.available() > 0) {
                return createCertificate(certBInputStream);

            } else
                throw new FileNotFoundException("Could not read stream");

        } catch (Exception e) {
            throw e;
        }
    }

    public static String encodeCertificate(Certificate cert) throws CertificateEncodingException {
        return Base64
                .getEncoder()
                .withoutPadding()
                .encodeToString(cert.getEncoded());
    }

    public static X509Certificate decodeCertificate(String base64EncodedCert) throws CertificateException {

        return createCertificate(
                new ByteArrayInputStream(
                        Base64.getDecoder()
                              .decode(base64EncodedCert)
                )
        );
    }

    public static void verifyCertificate(X509Certificate ca_cert, X509Certificate user_cert) throws CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        ca_cert.checkValidity();
//        ca_cert.verify(ca_cert.getPublicKey());
        user_cert.checkValidity();
        user_cert.verify(ca_cert.getPublicKey());
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

        System.out.println(user_cert.toString());

        try {

            verifyCertificate(ca_cert, user_cert);

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
