package org.example;

public class ServerApp {

    public static void main(String[] args) throws Exception {
        CryptoManager cryptoManager = new CryptoManager();
        ConnectionManager server = new ConnectionManager();
        server.startServerConnection(cryptoManager, args[0]);
        System.out.println(cryptoManager.rsaVerifyOperation());
    }
}
