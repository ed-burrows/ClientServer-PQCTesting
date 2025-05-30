package org.example;

import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;

import java.security.*;

public class DilithiumManager {

    @Deprecated
    public static KeyPair generateDilithium2KeyPair() throws InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Dilithium", "BCPQC");
        keyPairGenerator.initialize(DilithiumParameterSpec.dilithium2);
        return keyPairGenerator.generateKeyPair();
    }

    @Deprecated
    public static KeyPair generateDilithium3KeyPair() throws InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Dilithium", "BCPQC");
        keyPairGenerator.initialize(DilithiumParameterSpec.dilithium3);
        return keyPairGenerator.generateKeyPair();
    }

    @Deprecated
    public static KeyPair generateDilithium5KeyPair() throws InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Dilithium", "BCPQC");
        keyPairGenerator.initialize(DilithiumParameterSpec.dilithium5);
        return keyPairGenerator.generateKeyPair();
    }

    @Deprecated
    public static byte[] dilithiumSign(byte[] data, PrivateKey privateKey) throws NoSuchAlgorithmException,
            NoSuchProviderException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("Dilithium", "BCPQC");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    @Deprecated
    public static boolean dilithiumVerify(byte[] data, byte[] signature, PublicKey publicKey) throws NoSuchAlgorithmException,
            NoSuchProviderException, InvalidKeyException, SignatureException {
        Signature verifySignature = Signature.getInstance("Dilithium", "BCPQC");
        verifySignature.initVerify(publicKey);
        verifySignature.update(data);
        return verifySignature.verify(signature);
    }
}
