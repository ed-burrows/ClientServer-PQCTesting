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
            System.out.println("Secure server started on port " + PORT);
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
        BenchmarkLogger logger = BenchmarkLogger.getInstance();
        if (algorithm.equalsIgnoreCase("rsa3072") || algorithm.equalsIgnoreCase("rsa4096")) {
            logger.log("AlgorithmName", algorithm);
            System.out.println(cryptoManager.rsaVerifyOperation());
        } else if (algorithm.equalsIgnoreCase("mldsa44") || algorithm.equalsIgnoreCase("mldsa65") || algorithm.equalsIgnoreCase("mldsa87")) {
            logger.log("AlgorithmName", algorithm);
            System.out.println(cryptoManager.mldsaVerifyOperation());
        }
        logger.writeToCSV("serverresults.csv");
    }

    public void startClientConnection(CryptoManager cryptoManager, String algorithm, String serverAddress) throws Exception {
        BenchmarkLogger logger = BenchmarkLogger.getInstance();
        if (algorithm.equalsIgnoreCase("rsa3072")) {
            logger.log("AlgorithmName", algorithm);
            cryptoManager.rsa3072ClientOperation();
        } else if (algorithm.equalsIgnoreCase("rsa4096")) {
            logger.log("AlgorithmName", algorithm);
            cryptoManager.rsa4096ClientOperation();
        } else if (algorithm.equalsIgnoreCase("mldsa44")) {
            logger.log("AlgorithmName", algorithm);
            cryptoManager.mldsa44ClientOperation();
        } else if (algorithm.equalsIgnoreCase("mldsa65")) {
            logger.log("AlgorithmName", algorithm);
            cryptoManager.mldsa65ClientOperation();
        } else if (algorithm.equalsIgnoreCase("mldsa87")) {
            logger.log("AlgorithmName", algorithm);
            cryptoManager.mldsa87ClientOperation();
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
            long startTransfer;
            try (SSLSocket socket = (SSLSocket) sslSocketFactory.createSocket(serverAddress,PORT);
                 DataOutputStream output = new DataOutputStream(socket.getOutputStream());
                 DataInputStream input = new DataInputStream(socket.getInputStream())) {

                output.writeInt(FILES_TO_SEND.length);
                startTransfer = logger.startTimer();
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
            long transferTime = logger.stopTimer(startTransfer);
            logger.log("TransferTime(ms)", String.valueOf(transferTime));
            logger.printResults();
            logger.writeToCSV("clientresults.csv");
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
