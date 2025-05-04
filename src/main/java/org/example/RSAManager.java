package org.example;

import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

public class RSAManager {
    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(4096);
        return generator.generateKeyPair();
    }

    public static byte[] rsaSign(byte[] data, PrivateKey privateKey) throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException, SignatureException {
        Signature genSignature = Signature.getInstance("RSASSA-PSS");
        genSignature.setParameter(new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 32, 1));
        genSignature.initSign(privateKey);
        genSignature.update(data);
        return genSignature.sign();
    }

    public static boolean verify(byte[] data, byte[] signature, PublicKey publicKey) throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException, SignatureException {
        Signature verSignature = Signature.getInstance("RSASSA-PSS");
        verSignature.setParameter(new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 32, 1));
        verSignature.initVerify(publicKey);
        verSignature.update(data);
        return verSignature.verify(signature);
    }
}
