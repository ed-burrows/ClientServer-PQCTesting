package org.example;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;

public class FileHandler {

    public static void savePublicKey(Key key, String filepath) throws IOException {
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(filepath))){
            pemWriter.writeObject(key);
        }
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
