package org.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.interfaces.DilithiumPrivateKey;
import org.bouncycastle.pqc.jcajce.interfaces.DilithiumPublicKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;

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
        BenchmarkLogger logger = BenchmarkLogger.getInstance();
        logger.log("AlgorithmName", "RSA");
        long startKeyPair = logger.startTimer();
        KeyPair keyPair = RSAManager.generateRSAKeyPair();
        long timedKeyPair = logger.stopTimer(startKeyPair);
        logger.log("KeyPairGen(ms)", String.valueOf(timedKeyPair));
        logger.logSize("PrivKeySize(bytes)", keyPair.getPrivate().getEncoded());
        logger.logSize("PublicKeySize(bytes)", keyPair.getPublic().getEncoded());
        FileHandler.saveRSAKey(keyPair.getPrivate(), PRIVATE_KEY_FILE);
        FileHandler.saveRSAKey(keyPair.getPublic(), PUBLIC_KEY_FILE);
        long startSignatureGeneration = logger.startTimer();
        byte[] signature = RSAManager.rsaSign(Files.readAllBytes(MESSAGE_FILE_PATH), keyPair.getPrivate());
        long timedSignatureGeneration = logger.stopTimer(startSignatureGeneration);
        logger.log("SignatureGen(ms)", String.valueOf(timedSignatureGeneration));
        logger.logSize("SignatureSize(bytes)", signature);
        FileHandler.saveSignature(signature, SIGNATURE_FILE);
    }

    public void dilithium2ClientOperation() throws Exception {
        Security.addProvider(new BouncyCastlePQCProvider());
        BenchmarkLogger logger = BenchmarkLogger.getInstance();
        logger.log("AlgorithmName", "Dilithium2");
        long startKeyPair = logger.startTimer();
        KeyPair keyPair = DilithiumManager.generateDilithium2KeyPair();
        long timedKeyPair = logger.stopTimer(startKeyPair);
        DilithiumPrivateKey privateKey = (DilithiumPrivateKey) keyPair.getPrivate();
        DilithiumPublicKey publicKey = (DilithiumPublicKey) keyPair.getPublic();
        logger.log("KeyPairGen(ms)", String.valueOf(timedKeyPair));
        logger.logSize("PrivKeySize(bytes)", privateKey.getEncoded());
        logger.logSize("PublicKeySize(bytes)", publicKey.getEncoded());
        FileHandler.saveDilithiumKey(privateKey.getEncoded(), PRIVATE_KEY_FILE);
        FileHandler.saveDilithiumKey(publicKey.getEncoded(), PUBLIC_KEY_FILE);
        long startSignatureGeneration = logger.startTimer();
        byte[] signature = DilithiumManager.dilithiumSign(Files.readAllBytes(MESSAGE_FILE_PATH), privateKey);
        long timedSignatureGeneration = logger.stopTimer(startSignatureGeneration);
        logger.log("SignatureGen(ms)", String.valueOf(timedSignatureGeneration));
        logger.logSize("SignatureSize(bytes)", signature);
        FileHandler.saveSignature(signature, SIGNATURE_FILE);
    }

    public void dilithium3ClientOperation() throws Exception {
        Security.addProvider(new BouncyCastlePQCProvider());
        BenchmarkLogger logger = BenchmarkLogger.getInstance();
        logger.log("AlgorithmName", "Dilithium3");
        long startKeyPair = logger.startTimer();
        KeyPair keyPair = DilithiumManager.generateDilithium3KeyPair();
        long timedKeyPair = logger.stopTimer(startKeyPair);
        DilithiumPrivateKey privateKey = (DilithiumPrivateKey) keyPair.getPrivate();
        DilithiumPublicKey publicKey = (DilithiumPublicKey) keyPair.getPublic();
        logger.log("KeyPairGen(ms)", String.valueOf(timedKeyPair));
        logger.logSize("PrivKeySize(bytes)", privateKey.getEncoded());
        logger.logSize("PublicKeySize(bytes)", publicKey.getEncoded());
        FileHandler.saveDilithiumKey(privateKey.getEncoded(), PRIVATE_KEY_FILE);
        FileHandler.saveDilithiumKey(publicKey.getEncoded(), PUBLIC_KEY_FILE);
        long startSignatureGeneration = logger.startTimer();
        byte[] signature = DilithiumManager.dilithiumSign(Files.readAllBytes(MESSAGE_FILE_PATH), privateKey);
        long timedSignatureGeneration = logger.stopTimer(startSignatureGeneration);
        logger.log("SignatureGen(ms)", String.valueOf(timedSignatureGeneration));
        logger.logSize("SignatureSize(bytes)", signature);
        FileHandler.saveSignature(signature, SIGNATURE_FILE);
    }

    public void dilithium5ClientOperation() throws Exception {
        Security.addProvider(new BouncyCastlePQCProvider());
        BenchmarkLogger logger = BenchmarkLogger.getInstance();
        logger.log("AlgorithmName", "Dilithium5");
        long startKeyPair = logger.startTimer();
        KeyPair keyPair = DilithiumManager.generateDilithium5KeyPair();
        long timedKeyPair = logger.stopTimer(startKeyPair);
        DilithiumPrivateKey privateKey = (DilithiumPrivateKey) keyPair.getPrivate();
        DilithiumPublicKey publicKey = (DilithiumPublicKey) keyPair.getPublic();
        logger.log("KeyPairGen(ms)", String.valueOf(timedKeyPair));
        logger.logSize("PrivKeySize(bytes)", privateKey.getEncoded());
        logger.logSize("PublicKeySize(bytes)", publicKey.getEncoded());
        FileHandler.saveDilithiumKey(privateKey.getEncoded(), PRIVATE_KEY_FILE);
        FileHandler.saveDilithiumKey(publicKey.getEncoded(), PUBLIC_KEY_FILE);
        long startSignatureGeneration = logger.startTimer();
        byte[] signature = DilithiumManager.dilithiumSign(Files.readAllBytes(MESSAGE_FILE_PATH), privateKey);
        long timedSignatureGeneration = logger.stopTimer(startSignatureGeneration);
        logger.log("SignatureGen(ms)", String.valueOf(timedSignatureGeneration));
        logger.logSize("SignatureSize(bytes)", signature);
        FileHandler.saveSignature(signature, SIGNATURE_FILE);
    }

    public boolean rsaVerifyOperation() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        BenchmarkLogger logger = BenchmarkLogger.getInstance();
        logger.log("AlgorithmName", "RSA");
        PublicKey publicKey = FileHandler.readRSAKey(RECEIVED_KEY_FILE);
        long startSignatureVerification = logger.startTimer();
        boolean verifiedSignature = RSAManager.rsaVerify(Files.readAllBytes(RECEIVED_MESSAGE_FILEPATH), FileHandler.loadSignature(RECEIVED_SIGNATURE), publicKey);
        long signatureVerification = logger.stopTimer(startSignatureVerification);
        byte[] signature = FileHandler.loadSignature(RECEIVED_SIGNATURE);
        logger.logSize("PublicKeySize(bytes)", publicKey.getEncoded());
        logger.logSize("SignatureSize(bytes)", signature);
        logger.log("SignatureVerify(ms)", String.valueOf(signatureVerification));
        logger.log("VerificationResult", String.valueOf(verifiedSignature));
        return verifiedSignature;
    }

    public boolean dilithiumVerifyOperation() throws Exception {
        Security.addProvider(new BouncyCastlePQCProvider());
        BenchmarkLogger logger = BenchmarkLogger.getInstance();
        logger.log("AlgorithmName", "Dilithium");
        PublicKey publicKey = FileHandler.readDilithiumKey(RECEIVED_KEY_FILE);
        long startSignatureVerification = logger.startTimer();
        boolean verifiedSignature = DilithiumManager.dilithiumVerify(Files.readAllBytes(RECEIVED_MESSAGE_FILEPATH), FileHandler.loadSignature(RECEIVED_SIGNATURE), publicKey);
        long signatureVerification = logger.stopTimer(startSignatureVerification);
        byte[] signature = FileHandler.loadSignature(RECEIVED_SIGNATURE);
        logger.logSize("PublicKeySize(bytes)", publicKey.getEncoded());
        logger.logSize("SignatureSize(bytes)", signature);
        logger.log("SignatureVerify(ms)", String.valueOf(signatureVerification));
        logger.log("VerificationResult", String.valueOf(verifiedSignature));
        return verifiedSignature;
    }
}
