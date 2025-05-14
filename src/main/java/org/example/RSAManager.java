package org.example;

import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

public class RSAManager {


    public static KeyPair generateRSA3072KeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(3072, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    public static KeyPair generateRSA4096KeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(4096, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] rsaSign(byte[] data, PrivateKey privateKey) throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException, SignatureException {
        Signature genSignature = Signature.getInstance("RSASSA-PSS");
        genSignature.setParameter(new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 32, 1));
        genSignature.initSign(privateKey);
        genSignature.update(data);
        return genSignature.sign();
    }

    public static boolean rsaVerify(byte[] data, byte[] signature, PublicKey publicKey) throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException, SignatureException {
        Signature verSignature = Signature.getInstance("RSASSA-PSS");
        verSignature.setParameter(new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 32, 1));
        verSignature.initVerify(publicKey);
        verSignature.update(data);
        return verSignature.verify(signature);
    }
}
