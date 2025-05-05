package org.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Security;

public class ServerApp {
    private static final int PORT = 4444;
    private static final String MESSAGE_FILE = "receivedfiles/Hello.txt";
    private static final String SIGNATURE_FILE = "receivedfiles/signature.sig";
    private static final String PUBLIC_KEY_FILE = "receivedfiles/public_key.pem";
    private static final Path MESSAGE_FILEPATH = Paths.get(MESSAGE_FILE);
    private static SSLServerSocket serverSocket;
    private static boolean serverRunning = false;

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (FileInputStream keyStoreFile = new FileInputStream("server_keystore.p12")) {
                keyStore.load(keyStoreFile, "password".toCharArray());
            }

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(keyStore, "password".toCharArray());

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), null, null);

            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
            serverSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(PORT);
            serverSocket.setNeedClientAuth(false);
            System.out.println("Secure FTP server started on port " + PORT);
            serverRunning = true;

            while (serverRunning) {
                try {
                    SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                    new SessionHandler(clientSocket).start();
                } catch (IOException e) {
                    if (!serverRunning) break;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("Server shutdown.");
        Thread.sleep(1000);
        PublicKey publicKey = FileHandler.readPublicKey(PUBLIC_KEY_FILE);
        System.out.println(RSAManager.rsaVerify(Files.readAllBytes(MESSAGE_FILEPATH), FileHandler.loadSignature(SIGNATURE_FILE), publicKey));
    }
    public static void stopServer() {
        serverRunning = false;
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
