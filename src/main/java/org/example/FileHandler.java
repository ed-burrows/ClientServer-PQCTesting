package org.example;

import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class FileHandler {

    public static void saveRSAKey(Key key, String filepath) throws IOException {
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(filepath))){
            pemWriter.writeObject(key);
        }
    }

    public static PublicKey readRSAKey(String pemFilePath) throws Exception {
        try (FileReader keyReader = new FileReader(pemFilePath);
             PEMParser pemParser = new PEMParser(keyReader)) {

            Object object = pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

            if (object instanceof SubjectPublicKeyInfo) {
                return converter.getPublicKey((SubjectPublicKeyInfo) object);
            } else if (object instanceof RSAPublicKey rsaPublicKey) {
                RSAPublicKeySpec keySpec = new RSAPublicKeySpec(rsaPublicKey.getModulus(), rsaPublicKey.getPublicExponent());
                return KeyFactory.getInstance("RSA").generatePublic(keySpec);
            } else {
                throw new IllegalArgumentException("Unsupported PEM format");
            }
        }
    }

    public static void saveDilithiumKey(byte[] key, String filepath) throws IOException {
        Files.write(Paths.get(filepath), key);
    }

    public static PublicKey readDilithiumKey(String filepath) throws IOException, NoSuchAlgorithmException,
            NoSuchProviderException, InvalidKeySpecException {
        byte[] publicKeyBytes = Files.readAllBytes(Paths.get(filepath));
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("Dilithium", "BCPQC");
        return keyFactory.generatePublic(publicKeySpec);
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
