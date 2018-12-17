/**
 * Port forwarding server. Forward data
 * between two TCP ports. Based on Nakov TCP Socket Forward Server 
 * and adapted for IK2206.
 *
 * Original copyright notice below.
 * (c) 2018 Peter Sjodin, KTH
 */

/**
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */
 
import crypto.HandShakeCrypto;
import crypto.SessionDecrypter;
import crypto.SessionEncrypter;
import crypto.VerifyCertificate;
import vpnutil.*;

import java.lang.Integer;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class ForwardServer
{
    private static final boolean ENABLE_LOGGING = true;
    private static final int KEY_LENGTH = 256;
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "localhost";
    public static final String PROGRAMNAME = "ForwardServer";
    private static Arguments arguments;


    private ServerSocket handshakeSocket;

    private SessionEncrypter sessionEncrypter;
    private SessionDecrypter sessionDecrypter;
    private ServerSocket listenSocket;
    private String targetHost;
    private int targetPort;
    
    /**
     * Do handshake negotiation with client to authenticate, learn 
     * target host/port, etc.
     */
    private void doHandshake() throws UnknownHostException, IOException, Exception {

        Socket clientSocket = handshakeSocket.accept();
        String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
        Logger.log("Incoming handshake connection from " + clientHostPort);

        // RECV: ClientHello, Certificate
        // --------------------------------------------------------
        HandshakeMessage clientHelloMessage = new HandshakeMessage();
        clientHelloMessage.recv(clientSocket);
        if (!clientHelloMessage.getParameter("MessageType").equals("ClientHello")) {
            throw new InvalidHandshakeMessageException("Invalid start message from client");
        }

        log("Received client hello");

        X509Certificate ca_cert     = VerifyCertificate.readCertificate(arguments.get("cacert"));
        X509Certificate clientCert  = VerifyCertificate.decodeCertificate(clientHelloMessage.getParameter("Certificate"));
        VerifyCertificate.verifyCertificate(ca_cert, clientCert);

        log("Client certificate accepted: " + clientCert.getSubjectDN());


        // ServerHello, Certificate
        // --------------------------------------------------------
        Certificate serverCert = VerifyCertificate.readCertificate(arguments.get("usercert"));

        HandshakeMessage serverHelloMessage = new HandshakeMessage();
        serverHelloMessage.putParameter("MessageType", "ServerHello");
        serverHelloMessage.putParameter("Certificate", VerifyCertificate.encodeCertificate(serverCert));
        serverHelloMessage.send(clientSocket);

        log("Sent server hello");

        // RECV: Forward, TargetHost, TargetPort
        // --------------------------------------------------------
        HandshakeMessage clientConfigMessage = new HandshakeMessage();

        clientConfigMessage.recv(clientSocket);
        if (!clientConfigMessage.getParameter("MessageType").equals("Forward")) {
            throw new InvalidHandshakeMessageException("Expected message \"Forward\" but found type: " + clientConfigMessage.getParameter("MessageType"));
        }

        targetHost = clientConfigMessage.getParameter("TargetHost");
        targetPort = Integer.parseInt(clientConfigMessage.getParameter("TargetPort"));

        log("Received client configuration");


        // Session, SessionKey, SessionIV, ServerHost, ServerPort
        // --------------------------------------------------------

        listenSocket = new ServerSocket();
        listenSocket.bind(null);

        sessionEncrypter = new SessionEncrypter(KEY_LENGTH);
        sessionDecrypter = new SessionDecrypter(sessionEncrypter.encodeKey(), sessionEncrypter.encodeIV());

        PublicKey clientPublicKey = clientCert.getPublicKey();


        HandshakeMessage sessionMessage = new HandshakeMessage();

        byte[] crypto = HandShakeCrypto.encrypt(sessionEncrypter.encodeKey().getBytes(), clientPublicKey);
        String encryptedKey =  HandShakeCrypto.encodeByteArray(crypto);

        sessionMessage.putParameter("MessageType", "Session");
        sessionMessage.putParameter("SessionKey", HandShakeCrypto.encodeByteArray(HandShakeCrypto.encrypt(sessionEncrypter.encodeKey().getBytes(), clientPublicKey)));
        sessionMessage.putParameter("SessionIV", HandShakeCrypto.encodeByteArray(HandShakeCrypto.encrypt(sessionEncrypter.encodeIV().getBytes(), clientPublicKey)));
        sessionMessage.putParameter("ServerHost", listenSocket.getInetAddress().getHostAddress());
        sessionMessage.putParameter("ServerPort", Integer.toString(listenSocket.getLocalPort()));

        sessionMessage.send(clientSocket);

        log("Sent session message");

        clientSocket.close();
    }

    /**
     * Starts the forward server - binds on a given port and starts serving
     */
    public void startForwardServer()
    //throws IOException
        throws Exception
    {
 
        // Bind server on given TCP port
        int port = Integer.parseInt(arguments.get("handshakeport"));
        try {
            handshakeSocket = new ServerSocket(port);
        } catch (IOException ioe) {
           throw new IOException("Unable to bind to port " + port);
        }

        log("Nakov Forward Server started on TCP port " + port);
 
        // Accept client connections and process them until stopped
        while(true) {
            ForwardServerClientThread forwardThread;
           try {

               doHandshake();

               forwardThread = new ForwardServerClientThread(this.listenSocket, this.targetHost, this.targetPort, sessionEncrypter, sessionDecrypter);
               forwardThread.start();
           } catch (IOException e) {
               throw e;
           }
        }
    }
 
    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    public void log(String aMessage)
    {
        if (ENABLE_LOGGING)
           System.out.println(aMessage);
    }
 
    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--serverhost=<hostname>");
        System.err.println(indent + "--serverport=<portnumber>");        
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");                
    }
    
    /**
     * Program entry point. Reads settings, starts check-alive thread and
     * the forward server
     */
    public static void main(String[] args)
        throws Exception
    {
        arguments = new Arguments();
        arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
        arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
        arguments.loadArguments(args);
        
        ForwardServer srv = new ForwardServer();
        try {
           srv.startForwardServer();
        } catch (Exception e) {
           e.printStackTrace();
        }
    }
 
}
