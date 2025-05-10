package org.example;

public class ClientApp {
    public static void main(String[] args) throws Exception {
        CryptoManager cryptoManager = new CryptoManager();
        ConnectionManager client = new ConnectionManager();
        client.startClientConnection(cryptoManager, args[0], args[1]);
    }
}
