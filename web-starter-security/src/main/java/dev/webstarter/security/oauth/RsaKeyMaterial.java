package dev.webstarter.security.oauth;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import dev.webstarter.security.config.WebStarterSecurityProperties;

public record RsaKeyMaterial(RSAPublicKey publicKey, RSAPrivateKey privateKey) {

    public static RsaKeyMaterial from(WebStarterSecurityProperties properties) {
        if (hasText(properties.rsaPrivateKey()) && hasText(properties.rsaPublicKey())) {
            try {
                KeyFactory factory = KeyFactory.getInstance("RSA");
                RSAPrivateKey privateKey = (RSAPrivateKey) factory.generatePrivate(
                        new PKCS8EncodedKeySpec(decodePem(properties.rsaPrivateKey())));
                RSAPublicKey publicKey = (RSAPublicKey) factory.generatePublic(
                        new X509EncodedKeySpec(decodePem(properties.rsaPublicKey())));
                if (!privateKey.getModulus().equals(publicKey.getModulus())) {
                    throw new IllegalArgumentException("OAuth RSA public and private keys do not match");
                }
                return new RsaKeyMaterial(publicKey, privateKey);
            }
            catch (Exception ex) {
                throw new IllegalStateException("Invalid OAuth RSA key material", ex);
            }
        }
        if (!properties.developmentKeysAllowed()) {
            throw new IllegalStateException(
                    "OAuth RSA keys are required; ephemeral keys are allowed only for development");
        }
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(3072);
            KeyPair keyPair = generator.generateKeyPair();
            return new RsaKeyMaterial(
                    (RSAPublicKey) keyPair.getPublic(), (RSAPrivateKey) keyPair.getPrivate());
        }
        catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("RSA is unavailable", ex);
        }
    }

    private static byte[] decodePem(String pem) {
        String value = pem
                .replaceAll("-----BEGIN [^-]+-----", "")
                .replaceAll("-----END [^-]+-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(value);
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
