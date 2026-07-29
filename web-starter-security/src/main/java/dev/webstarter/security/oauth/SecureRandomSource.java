package dev.webstarter.security.oauth;

import java.security.SecureRandom;

@FunctionalInterface
interface SecureRandomSource {

    void nextBytes(byte[] value);

    static SecureRandomSource system() {
        SecureRandom secureRandom = new SecureRandom();
        return secureRandom::nextBytes;
    }
}
