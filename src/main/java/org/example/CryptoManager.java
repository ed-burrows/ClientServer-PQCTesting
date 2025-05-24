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

    public void rsa3072ClientOperation() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        BenchmarkLogger logger = BenchmarkLogger.getInstance();
        long startKeyPair = logger.startTimer();
        KeyPair keyPair = RSAManager.generateRSA3072KeyPair();
        long timedKeyPair = logger.stopTimer(startKeyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        logger.log("KeyPairGen(ms)", String.valueOf(timedKeyPair));
        logger.logSize("PrivKeySize(bytes)", privateKey.getEncoded());
        logger.logSize("PublicKeySize(bytes)", publicKey.getEncoded());
        FileHandler.saveRSAKeys(privateKey, PRIVATE_KEY_FILE, publicKey, PUBLIC_KEY_FILE);
        long startSignatureGeneration = logger.startTimer();
        byte[] signature = RSAManager.rsaSign(Files.readAllBytes(MESSAGE_FILE_PATH), privateKey);
        long timedSignatureGeneration = logger.stopTimer(startSignatureGeneration);
        logger.log("SignatureGen(ms)", String.valueOf(timedSignatureGeneration));
        logger.logSize("SignatureSize(bytes)", signature);
        FileHandler.saveSignature(signature, SIGNATURE_FILE);
    }

    public void rsa4096ClientOperation() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        BenchmarkLogger logger = BenchmarkLogger.getInstance();
        long startKeyPair = logger.startTimer();
        KeyPair keyPair = RSAManager.generateRSA4096KeyPair();
        long timedKeyPair = logger.stopTimer(startKeyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        logger.log("KeyPairGen(ms)", String.valueOf(timedKeyPair));
        logger.logSize("PrivKeySize(bytes)", privateKey.getEncoded());
        logger.logSize("PublicKeySize(bytes)", publicKey.getEncoded());
        FileHandler.saveRSAKeys(privateKey, PRIVATE_KEY_FILE, publicKey, PUBLIC_KEY_FILE);
        long startSignatureGeneration = logger.startTimer();
        byte[] signature = RSAManager.rsaSign(Files.readAllBytes(MESSAGE_FILE_PATH), privateKey);
        long timedSignatureGeneration = logger.stopTimer(startSignatureGeneration);
        logger.log("SignatureGen(ms)", String.valueOf(timedSignatureGeneration));
        logger.logSize("SignatureSize(bytes)", signature);
        FileHandler.saveSignature(signature, SIGNATURE_FILE);
    }

    public void dilithium2ClientOperation() throws Exception {
        Security.addProvider(new BouncyCastlePQCProvider());
        BenchmarkLogger logger = BenchmarkLogger.getInstance();
        long startKeyPair = logger.startTimer();
        KeyPair keyPair = DilithiumManager.generateDilithium2KeyPair();
        long timedKeyPair = logger.stopTimer(startKeyPair);
        DilithiumPrivateKey privateKey = (DilithiumPrivateKey) keyPair.getPrivate();
        DilithiumPublicKey publicKey = (DilithiumPublicKey) keyPair.getPublic();
        logger.log("KeyPairGen(ms)", String.valueOf(timedKeyPair));
        logger.logSize("PrivKeySize(bytes)", privateKey.getEncoded());
        logger.logSize("PublicKeySize(bytes)", publicKey.getEncoded());
        FileHandler.saveDilithiumKeys(privateKey, PRIVATE_KEY_FILE, publicKey, PUBLIC_KEY_FILE);
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
        long startKeyPair = logger.startTimer();
        KeyPair keyPair = DilithiumManager.generateDilithium3KeyPair();
        long timedKeyPair = logger.stopTimer(startKeyPair);
        DilithiumPrivateKey privateKey = (DilithiumPrivateKey) keyPair.getPrivate();
        DilithiumPublicKey publicKey = (DilithiumPublicKey) keyPair.getPublic();
        logger.log("KeyPairGen(ms)", String.valueOf(timedKeyPair));
        logger.logSize("PrivKeySize(bytes)", privateKey.getEncoded());
        logger.logSize("PublicKeySize(bytes)", publicKey.getEncoded());
        FileHandler.saveDilithiumKeys(privateKey, PRIVATE_KEY_FILE, publicKey, PUBLIC_KEY_FILE);
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
        long startKeyPair = logger.startTimer();
        KeyPair keyPair = DilithiumManager.generateDilithium5KeyPair();
        long timedKeyPair = logger.stopTimer(startKeyPair);
        DilithiumPrivateKey privateKey = (DilithiumPrivateKey) keyPair.getPrivate();
        DilithiumPublicKey publicKey = (DilithiumPublicKey) keyPair.getPublic();
        logger.log("KeyPairGen(ms)", String.valueOf(timedKeyPair));
        logger.logSize("PrivKeySize(bytes)", privateKey.getEncoded());
        logger.logSize("PublicKeySize(bytes)", publicKey.getEncoded());
        FileHandler.saveDilithiumKeys(privateKey, PRIVATE_KEY_FILE, publicKey, PUBLIC_KEY_FILE);
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
        PublicKey publicKey = FileHandler.loadRSAPublicKey(RECEIVED_KEY_FILE);
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
        PublicKey publicKey = FileHandler.loadDilithiumPublicKey(RECEIVED_KEY_FILE);
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

    public void mldsa44ClientOperation() throws Exception {
        BenchmarkLogger logger = BenchmarkLogger.getInstance();
        long startKeyPair = logger.startTimer();
        KeyPair keyPair = MLDSAManager.generateMLDSA44KeyPair();
        long timedKeyPair = logger.stopTimer(startKeyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        logger.log("KeyPairGen(ms)", String.valueOf(timedKeyPair));
        logger.logSize("PrivKeySize(bytes)", privateKey.getEncoded());
        logger.logSize("PublicKeySize(bytes)", publicKey.getEncoded());
        FileHandler.saveMLDSAKeys(PUBLIC_KEY_FILE, publicKey);
        long startSignatureGeneration = logger.startTimer();
        byte[] signature = MLDSAManager.mldsaSign(Files.readAllBytes(MESSAGE_FILE_PATH), privateKey);
        long timedSignatureGeneration = logger.stopTimer(startSignatureGeneration);
        logger.log("SignatureGen(ms)", String.valueOf(timedSignatureGeneration));
        logger.logSize("SignatureSize(bytes)", signature);
        FileHandler.saveSignature(signature, SIGNATURE_FILE);
    }

    public void mldsa65ClientOperation() throws Exception {
        BenchmarkLogger logger = BenchmarkLogger.getInstance();
        long startKeyPair = logger.startTimer();
        KeyPair keyPair = MLDSAManager.generateMLDSA65KeyPair();
        long timedKeyPair = logger.stopTimer(startKeyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        logger.log("KeyPairGen(ms)", String.valueOf(timedKeyPair));
        logger.logSize("PrivKeySize(bytes)", privateKey.getEncoded());
        logger.logSize("PublicKeySize(bytes)", publicKey.getEncoded());
        FileHandler.saveMLDSAKeys(PUBLIC_KEY_FILE, publicKey);
        long startSignatureGeneration = logger.startTimer();
        byte[] signature = MLDSAManager.mldsaSign(Files.readAllBytes(MESSAGE_FILE_PATH), privateKey);
        long timedSignatureGeneration = logger.stopTimer(startSignatureGeneration);
        logger.log("SignatureGen(ms)", String.valueOf(timedSignatureGeneration));
        logger.logSize("SignatureSize(bytes)", signature);
        FileHandler.saveSignature(signature, SIGNATURE_FILE);
    }

    public void mldsa87ClientOperation() throws Exception {
        BenchmarkLogger logger = BenchmarkLogger.getInstance();
        long startKeyPair = logger.startTimer();
        KeyPair keyPair = MLDSAManager.generateMLDSA87KeyPair();
        long timedKeyPair = logger.stopTimer(startKeyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        logger.log("KeyPairGen(ms)", String.valueOf(timedKeyPair));
        logger.logSize("PrivKeySize(bytes)", privateKey.getEncoded());
        logger.logSize("PublicKeySize(bytes)", publicKey.getEncoded());
        FileHandler.saveMLDSAKeys(PUBLIC_KEY_FILE, publicKey);
        long startSignatureGeneration = logger.startTimer();
        byte[] signature = MLDSAManager.mldsaSign(Files.readAllBytes(MESSAGE_FILE_PATH), privateKey);
        long timedSignatureGeneration = logger.stopTimer(startSignatureGeneration);
        logger.log("SignatureGen(ms)", String.valueOf(timedSignatureGeneration));
        logger.logSize("SignatureSize(bytes)", signature);
        FileHandler.saveSignature(signature, SIGNATURE_FILE);
    }

    public boolean mldsaVerifyOperation() throws Exception {
        BenchmarkLogger logger = BenchmarkLogger.getInstance();
        PublicKey publicKey = FileHandler.loadMLDSAPublicKey(RECEIVED_KEY_FILE);
        long startSignatureVerification = logger.startTimer();
        boolean verifiedSignature = MLDSAManager.mldsaVerify(Files.readAllBytes(RECEIVED_MESSAGE_FILEPATH), FileHandler.loadSignature(RECEIVED_SIGNATURE), publicKey);
        long signatureVerification = logger.stopTimer(startSignatureVerification);
        byte[] signature = FileHandler.loadSignature(RECEIVED_SIGNATURE);
        logger.logSize("PublicKeySize(bytes)", publicKey.getEncoded());
        logger.logSize("SignatureSize(bytes)", signature);
        logger.log("SignatureVerify(ms)", String.valueOf(signatureVerification));
        logger.log("VerificationResult", String.valueOf(verifiedSignature));
        return verifiedSignature;
    }
}
