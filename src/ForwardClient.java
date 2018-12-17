/**
 * Port forwarding client. Forward data
 * between two TCP ports. Based on Nakov TCP Socket Forward Server 
 * and adapted for IK2206.
 *
 * See original copyright notice below.
 * (c) 2018 Peter Sjodin, KTH
 */

/**
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */

 
import crypto.*;
import vpnutil.Arguments;
import vpnutil.ForwardServerClientThread;
import vpnutil.HandshakeMessage;
import vpnutil.InvalidHandshakeMessageException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.lang.IllegalArgumentException;
import java.lang.Integer;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

import static java.lang.System.exit;

public class ForwardClient
{
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "localhost";
    public static final String PROGRAMNAME = "ForwardClient";

    private static Arguments arguments;
    private static int serverPort;
    private static String serverHost;
    private static SessionDecrypter sessionDecrypter;
    private static SessionEncrypter sessionEncrypter;

    private static void doHandshake() throws IOException, CertificateException, InvalidHandshakeMessageException, InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException, SignatureException {

        log("Performing crypto handshake.");

        /* Connect to forward server server */
        System.out.println("Connect to " +  arguments.get("handshakehost") + ":" + Integer.parseInt(arguments.get("handshakeport")));
        Socket serverSocket = new Socket(arguments.get("handshakehost"), Integer.parseInt(arguments.get("handshakeport")));

        // ClientHello, Certificate
        // --------------------------------------------------------
        Certificate clientcert = VerifyCertificate.readCertificate(arguments.get("usercert"));

        HandshakeMessage clienthello = new HandshakeMessage();
        clienthello.putParameter("MessageType", "ClientHello");
        clienthello.putParameter("Certificate", VerifyCertificate.encodeCertificate(clientcert));
        clienthello.send(serverSocket);

        log("Sent client hello");

        // RECV: ServerHello, Certificate
        // --------------------------------------------------------
        HandshakeMessage serverHello = new HandshakeMessage();
        serverHello.recv(serverSocket);

        if (!serverHello.getParameter("MessageType").equals("ServerHello")) {
            throw new InvalidHandshakeMessageException("Expected message \"ServerHello\" but found type: " + serverHello.getParameter("MessageType"));
        }

        log("Received server hello");

        X509Certificate ca_cert     = VerifyCertificate.readCertificate(arguments.get("cacert"));
        X509Certificate serverCert  = VerifyCertificate.decodeCertificate(serverHello.getParameter("Certificate"));
        VerifyCertificate.verifyCertificate(ca_cert, serverCert);

        log("Server certificate accepted: " + serverCert.getSubjectDN());

        // Forward, TargetHost, TargetPort
        // --------------------------------------------------------
        HandshakeMessage clientConfigMessage = new HandshakeMessage();
        clientConfigMessage.putParameter("MessageType", "Forward");
        clientConfigMessage.putParameter("TargetHost", arguments.get("targethost"));
        clientConfigMessage.putParameter("TargetPort", arguments.get("targetport"));
        clientConfigMessage.send(serverSocket);

        log("Sent configuration options");


        // RECV: Session, SessionKey, SessionIV, ServerHost, ServerPort
        // --------------------------------------------------------
        HandshakeMessage sessionMessage = new HandshakeMessage();
        PrivateKey privateKey = HandShakeCrypto.getPrivateKeyFromKeyFile(arguments.get("key"));

        sessionMessage.recv(serverSocket);
        if (!sessionMessage.getParameter("MessageType").equals("Session")) {
            throw new InvalidHandshakeMessageException("Expected message \"Session\" but found type: " + sessionMessage.getParameter("MessageType"));
        }

        // Decrypt the session key and IV and create a new session decryptor.
        String encodedSessionKey =
                new String(
                    HandShakeCrypto.decrypt(
                        HandShakeCrypto.decodeString(sessionMessage.getParameter("SessionKey")),
                        privateKey
                    )
                );

        String encodedIV =
                new String(
                    HandShakeCrypto.decrypt(
                        HandShakeCrypto.decodeString(sessionMessage.getParameter("SessionIV")),
                        privateKey
                    )
                );

        // Create both encryptor and decryptor for the same key as we need to encrypt and decrypt
        // traffic to have a bidirectional stream
        sessionDecrypter = new SessionDecrypter(encodedSessionKey, encodedIV);
        sessionEncrypter = new SessionEncrypter(encodedSessionKey, encodedIV);


        serverHost = sessionMessage.getParameter("ServerHost");
        serverPort = Integer.parseInt(sessionMessage.getParameter("ServerPort"));

        log("Received encryption parameters. Handshake successful!");

        // DONE!

        serverSocket.close();
    }



    /*
     * Let user know that we are waiting
     */
    private static void tellUser(ServerSocket listensocket) throws UnknownHostException {
        System.out.println("Client forwarder to target " + arguments.get("targethost") + ":" + arguments.get("targetport"));
        System.out.println("Waiting for incoming connections at " +
                           InetAddress.getLocalHost().getHostAddress() + ":" + listensocket.getLocalPort());
    }
        
    /*
     * Set up client forwarder.
     * Run handshake negotiation, then set up a listening socket and wait for user.
     * When user has connected, start port forwarder thread.
     */
    static public void startForwardClient() throws IOException {

        try {
            doHandshake();
        } catch (Exception e) {
          e.printStackTrace();
          exit(-1);
        }
//        catch (CertificateException e) {
//            e.printStackTrace();
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        } catch (InvalidKeyException e) {
//            e.printStackTrace();
//        } catch (vpnutil.InvalidHandshakeMessageException e) {
//            e.printStackTrace();
//        } catch (NoSuchPaddingException e) {
//            e.printStackTrace();
//        } catch (BadPaddingException e) {
//            e.printStackTrace();
//        } catch (InvalidKeySpecException e) {
//            e.printStackTrace();
//        } catch (IllegalBlockSizeException e) {
//            e.printStackTrace();
//        } catch (InvalidAlgorithmParameterException e) {
//            e.printStackTrace();
//        }

        // Wait for client. Accept one connection.
        ForwardServerClientThread forwardThread;
        ServerSocket listensocket;
        
        try {
            /* Create a new socket. This is to where the user should connect.
             * ForwardClient sets up port forwarding between this socket
             * and the ServerHost/ServerPort learned from the handshake */
            listensocket = new ServerSocket();
            /* Let the system pick a port number */
            listensocket.bind(null); 
            /* Tell the user, so the user knows where to connect */ 
            tellUser(listensocket);

            Socket clientSocket = listensocket.accept();
            String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
            log("Accepted client from " + clientHostPort);
            
            forwardThread = new ForwardServerClientThread(clientSocket, serverHost, serverPort, sessionEncrypter, sessionDecrypter);
            forwardThread.start();
            
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println(e);
            throw e;
        }
    }

    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    public static void log(String aMessage)
    {
        if (ENABLE_LOGGING)
           System.out.println(aMessage);
    }
 
    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--targethost=<hostname>");
        System.err.println(indent + "--targetport=<portnumber>");        
        System.err.println(indent + "--handshakehost=<hostname>");
        System.err.println(indent + "--handshakeport=<portnumber>");        
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");                
    }
    
    /**
     * Program entry point. Reads arguments and run
     * the forward server
     */
    public static void main(String[] args)
    {
        try {
            arguments = new Arguments();
            arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
            arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
            arguments.loadArguments(args);
            if (arguments.get("targetport") == null || arguments.get("targethost") == null) {
                throw new IllegalArgumentException("Target not specified");
            }
        } catch(IllegalArgumentException ex) {
            System.out.println(ex);
            usage();
            exit(1);
        }
        try {
            startForwardClient();
        } catch(IOException e) {
           e.printStackTrace();
        }
    }
}
