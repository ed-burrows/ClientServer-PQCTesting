package org.example;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;

public class ServerApp {
    private static final int PORT = 4444;
    private static SSLServerSocket serverSocket;
    private static boolean serverRunning = false;

    public static void main(String[] args) throws Exception {
//        Security.addProvider(new BouncyCastleProvider());
        CryptoManager cryptoManager = new CryptoManager();

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
            System.out.println("Error: " + e.getMessage());
        }
        System.out.println("Server shutdown.");
        Thread.sleep(1000);
        System.out.println(cryptoManager.rsaVerifyOperation());
    }
    public static void stopServer() {
        serverRunning = false;
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
}
