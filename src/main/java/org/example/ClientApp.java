package org.example;

import java.nio.file.Files;
import java.nio.file.Path;

public class ClientApp {
    public static void main(String[] args) throws Exception {
        CryptoManager cryptoManager = new CryptoManager();
        ConnectionManager client = new ConnectionManager();
        client.startClientConnection(cryptoManager, args[0], args[1]);
        System.out.println(cryptoManager.rsaVerifyOperation());
    }
}
