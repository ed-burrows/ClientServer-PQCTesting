package org.example;

import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;

public class ConnectionManager {
    private static final int PORT = 4444;
    private static SSLServerSocket serverSocket;
    private static boolean serverRunning = false;
    private static final String MESSAGE_FILE = "filestosend/Hello.txt";
    private static final String SIGNATURE_FILE = "filestosend/signature.sig";
    private static final String PUBLIC_KEY_FILE = "filestosend/public_key.pem";
    private static final String[] FILES_TO_SEND = {MESSAGE_FILE, SIGNATURE_FILE, PUBLIC_KEY_FILE};

    public void startServerConnection(CryptoManager cryptoManager, String algorithm) throws Exception {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (FileInputStream keyStoreFile = new FileInputStream("server_keystore.p12")) {
                keyStore.load(keyStoreFile, "password".toCharArray());
            }

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(keyStore,"password".toCharArray());

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
        if (algorithm.equalsIgnoreCase("rsa")) {
            System.out.println(cryptoManager.rsaVerifyOperation());
        } else if (algorithm.equalsIgnoreCase("dilithium")) {
            System.out.println(cryptoManager.dilithiumVerifyOperation());
        }
    }

    public void startClientConnection(CryptoManager cryptoManager, String algorithm, String serverAddress) throws Exception {
        if (algorithm.equalsIgnoreCase("rsa")) {
            cryptoManager.rsaClientOperation();
        } else if (algorithm.equalsIgnoreCase("dilithium2")) {
            cryptoManager.dilithium2ClientOperation();
        } else if (algorithm.equalsIgnoreCase("dilithium3")) {
            cryptoManager.dilithium3ClientOperation();
        } else if (algorithm.equalsIgnoreCase("dilithium5")) {
            cryptoManager.dilithium5ClientOperation();
        }
        try {
            KeyStore trustStore = KeyStore.getInstance("PKCS12");
            try (FileInputStream trustStoreFile = new FileInputStream("client_truststore.p12")) {
                trustStore.load(trustStoreFile, "password".toCharArray());
            }

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
            trustManagerFactory.init(trustStore);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
            try (SSLSocket socket = (SSLSocket) sslSocketFactory.createSocket(serverAddress,PORT);
                 DataOutputStream output = new DataOutputStream(socket.getOutputStream());
                 DataInputStream input = new DataInputStream(socket.getInputStream())) {

                output.writeInt(FILES_TO_SEND.length);

                for (String filename : FILES_TO_SEND) {
                    File file = new File(filename);
                    if (!file.exists()) {
                        System.out.println("File not found: " + filename);
                        continue;
                    }
                    output.writeUTF(file.getName());
                    output.writeLong(file.length());

                    try (FileInputStream fileInputStream = new FileInputStream(file)) {
                        byte[] buffer = new byte[4096];
                        int bytesRead;
                        while ((bytesRead = fileInputStream.read(buffer)) != -1) {
                            output.write(buffer,0,bytesRead);
                        }
                    }
                    String response = input.readUTF();
                    System.out.println("Server response: " + response);
                }
                output.writeUTF("END_TRANSFER");
                System.out.println("All files send successfully. Server shutdown signal sent.");
            }
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
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
