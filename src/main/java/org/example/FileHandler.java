package org.example;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

public class FileHandler {

    public static void saveKeyToFile(String filename, String description, byte[] keyBytes) throws IOException {
        PemObject pemObject = new PemObject(description, keyBytes);
        try (PemWriter pemWriter = new PemWriter(new FileWriter(filename))) {
            pemWriter.writeObject(pemObject);
        }
    }

    public static void saveRSAKeys(PrivateKey privateKey, String privKeyFilepath, PublicKey publicKey, String pubKeyFilepath) throws IOException {
        saveKeyToFile(privKeyFilepath, "RSA PRIVATE KEY", privateKey.getEncoded());
        saveKeyToFile(pubKeyFilepath, "RSA PUBLIC KEY", publicKey.getEncoded());
    }

    public static void saveDilithiumKeys(PrivateKey privateKey, String privKeyFilepath, PublicKey publicKey,String pubKeyFilepath) throws IOException {
        saveKeyToFile(privKeyFilepath, "DILITHIUM PRIVATE KEY", privateKey.getEncoded());
        saveKeyToFile(pubKeyFilepath, "DILITHIUM PUBLIC KEY", publicKey.getEncoded());
    }

    public static PublicKey loadRSAPublicKey(String filepath) throws Exception {
        try (PemReader pemReader = new PemReader(new FileReader(filepath))) {
            PemObject pemObject = pemReader.readPemObject();
            byte[] keyBytes = pemObject.getContent();
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            return keyFactory.generatePublic(keySpec);
        }
    }

    public static PublicKey loadDilithiumPublicKey(String filepath) throws Exception {
        try (PemReader pemReader = new PemReader(new FileReader(filepath))) {
            PemObject pemObject = pemReader.readPemObject();
            byte[] keyBytes = pemObject.getContent();
            KeyFactory keyFactory = KeyFactory.getInstance("Dilithium", "BCPQC");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            return keyFactory.generatePublic(keySpec);
        }
    }

    public static void saveMLDSAKeys(String filepath, PublicKey publicKey) throws IOException {
        Files.write(Path.of(filepath), publicKey.getEncoded());
    }

    public static PublicKey loadMLDSAPublicKey(String filepath) throws Exception {
        byte[] pubKeyBytes = Files.readAllBytes(Path.of(filepath));
        KeyFactory factory = KeyFactory.getInstance("ML-DSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pubKeyBytes);
        return factory.generatePublic(publicKeySpec);
    }

    public static void saveSignature(byte[] signature, String filepath) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filepath)) {
            fos.write(signature);
        }
    }

    public static byte[] loadSignature(String filepath) throws IOException {
        return Files.readAllBytes(Paths.get(filepath));
    }
}
