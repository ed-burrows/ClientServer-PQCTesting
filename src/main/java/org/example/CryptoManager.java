package org.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;

public class CryptoManager {
    private static final String MESSAGE_FILE = "filestosend/Hello.txt";
    private static final String SIGNATURE_FILE = "filestosend/signature.sig";
    private static final String PUBLIC_KEY_FILE = "filestosend/public_key.pem";
    private static final String PRIVATE_KEY_FILE = "filestosend/private_key.pem";
    private static final Path MESSAGE_FILE_PATH = Path.of(MESSAGE_FILE);
    private static final String RECEIVED_KEY_FILE = "receivedfiles/public_key.pem";
    private static final String RECEIVED_MESSAGE = "receivedfiles/Hello.txt";
    private static final String RECEIVED_SIGNATURE = "receivedfiles/signature.sig";
    private static final Path RECEIVED_MESSAGE_FILEPATH = Paths.get(RECEIVED_MESSAGE);

    public CryptoManager() {}

    public void rsaClientOperation() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPair keyPair = RSAManager.generateRSAKeyPair();
        FileHandler.saveKeyFile(keyPair.getPrivate(), PRIVATE_KEY_FILE);
        FileHandler.saveKeyFile(keyPair.getPublic(), PUBLIC_KEY_FILE);
        byte[] signature = RSAManager.rsaSign(Files.readAllBytes(MESSAGE_FILE_PATH), keyPair.getPrivate());
        FileHandler.saveSignature(signature, SIGNATURE_FILE);
    }

    public void dilithium2ClientOperation() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPair keyPair = DilithiumManager.generateDilithium2KeyPair();
        FileHandler.saveKeyFile(keyPair.getPrivate(), PRIVATE_KEY_FILE);
        FileHandler.saveKeyFile(keyPair.getPublic(), PUBLIC_KEY_FILE);
        byte[] signature = DilithiumManager.dilithiumSign(Files.readAllBytes(MESSAGE_FILE_PATH), keyPair.getPrivate());
        FileHandler.saveSignature(signature, SIGNATURE_FILE);
    }

    public void dilithium3ClientOperation() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPair keyPair = DilithiumManager.generateDilithium3KeyPair();
        FileHandler.saveKeyFile(keyPair.getPrivate(), PRIVATE_KEY_FILE);
        FileHandler.saveKeyFile(keyPair.getPublic(), PUBLIC_KEY_FILE);
        byte[] signature = DilithiumManager.dilithiumSign(Files.readAllBytes(MESSAGE_FILE_PATH), keyPair.getPrivate());
        FileHandler.saveSignature(signature, SIGNATURE_FILE);
    }

    public void dilithium5ClientOperation() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPair keyPair = DilithiumManager.generateDilithium5KeyPair();
        FileHandler.saveKeyFile(keyPair.getPrivate(), PRIVATE_KEY_FILE);
        FileHandler.saveKeyFile(keyPair.getPublic(), PUBLIC_KEY_FILE);
        byte[] signature = DilithiumManager.dilithiumSign(Files.readAllBytes(MESSAGE_FILE_PATH), keyPair.getPrivate());
        FileHandler.saveSignature(signature, SIGNATURE_FILE);
    }

    public boolean rsaVerifyOperation() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        PublicKey publicKey = FileHandler.readPublicKey(RECEIVED_KEY_FILE);
        return RSAManager.rsaVerify(Files.readAllBytes(RECEIVED_MESSAGE_FILEPATH), FileHandler.loadSignature(RECEIVED_SIGNATURE), publicKey);
    }
}
