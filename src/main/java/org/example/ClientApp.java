package org.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Security;

public class ClientApp {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int PORT = 4444;
    private static final String MESSAGE_FILE = "filestosend/Hello.txt";
    private static final String SIGNATURE_FILE = "filestosend/signature.sig";
    private static final String PUBLIC_KEY_FILE = "filestosend/public_key.pem";
    private static final String PRIVATE_KEY_FILE = "filestosend/private_key.pem";
    private static final Path MESSAGE_FILE_PATH = Path.of(MESSAGE_FILE);
    private static final String[] FILES_TO_SEND = {MESSAGE_FILE, SIGNATURE_FILE, PUBLIC_KEY_FILE};

    public static void main(String[] args) throws Exception {
        CryptoManager cryptoManager = new CryptoManager();
        if (args[0].equalsIgnoreCase("rsa")) {
            cryptoManager.rsaClientOperation();
        } else if (args[0].equalsIgnoreCase("dilithium2")) {
            cryptoManager.dilithium2ClientOperation();
        } else if (args[0].equalsIgnoreCase("dilithium3")) {
            cryptoManager.dilithium3ClientOperation();
        } else if (args[0].equalsIgnoreCase("dilithium5")) {
            cryptoManager.dilithium5ClientOperation();
        }
        System.out.println(RSAManager.rsaVerify(Files.readAllBytes(MESSAGE_FILE_PATH), FileHandler.loadSignature(SIGNATURE_FILE), FileHandler.readPublicKey(PUBLIC_KEY_FILE)));
        Thread.sleep(1000);
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
            try (SSLSocket socket = (SSLSocket) sslSocketFactory.createSocket(SERVER_ADDRESS,PORT);
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
                            output.write(buffer, 0, bytesRead);
                        }
                    }

                    String response = input.readUTF();
                    System.out.println("Server response: " + response);
                }
                output.writeUTF("END_TRANSFER");

                System.out.println("All files sent successfully. Server shutdown signal sent.");
            }
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());;
        }
    }
}
