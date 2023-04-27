package br.dev.webit.totp;

import java.security.SecureRandom;

public class SecretGenerator {

    private static final SecureRandom RANDOM = new SecureRandom();
    private final int size;

    public SecretGenerator(int size) {
        this.size = size;
    }

    public byte[] generate() {
        byte[] secret = new byte[size];
        RANDOM.nextBytes(secret);
        return secret;
    }
}
