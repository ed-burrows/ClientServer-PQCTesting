package org.example;

import java.security.*;
import java.security.spec.NamedParameterSpec;

public class MLDSAManager {
    public static KeyPair generateMLDSA44KeyPair() throws InvalidAlgorithmParameterException,
            NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ML-DSA");
        keyPairGenerator.initialize(NamedParameterSpec.ML_DSA_44);
        return keyPairGenerator.generateKeyPair();
    }

    public static KeyPair generateMLDSA65KeyPair() throws InvalidAlgorithmParameterException,
            NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ML-DSA");
        keyPairGenerator.initialize(NamedParameterSpec.ML_DSA_65);
        return keyPairGenerator.generateKeyPair();
    }

    public static KeyPair generateMLDSA87KeyPair() throws InvalidAlgorithmParameterException,
            NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ML-DSA");
        keyPairGenerator.initialize(NamedParameterSpec.ML_DSA_87);
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] mldsaSign(byte[] data, PrivateKey privateKey) throws NoSuchAlgorithmException,
            InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("ML-DSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    public static boolean mldsaVerify(byte[] data, byte[] signature, PublicKey publicKey) throws NoSuchAlgorithmException,
            InvalidKeyException, SignatureException {
        Signature verifySignature = Signature.getInstance("ML-DSA");
        verifySignature.initVerify(publicKey);
        verifySignature.update(data);
        return verifySignature.verify(signature);
    }
}
