package org.example;

import javax.net.ssl.SSLServerSocket;
import java.nio.file.Path;
import java.nio.file.Paths;

public class ServerApp {
    private static final int PORT = 4444;
    private static final String MESSAGE_FILE = "receivedfiles/Hello.txt";
    private static final String SIGNATURE_FILE = "receivedfiles/signature.sig";
    private static final String PUBLIC_KEY_FILE = "receivedfiles/public_key.pem";
    private static final Path MESSAGE_FILEPATH = Paths.get(MESSAGE_FILE);
    private static SSLServerSocket serverSocket;
    private static boolean serverRunning = false;

    public static void main(String[] args) {

    }

    public static void stopServer() {

    }
}
