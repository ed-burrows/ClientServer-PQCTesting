package org.example;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.FileWriter;
import java.io.IOException;
import java.security.Key;

public class FileHandler {

    public static void savePublicKey(Key key, String filepath) throws IOException {
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(filepath))){
            pemWriter.writeObject(key);
        }
    }
}
