package br.dev.webit.totp;

import java.security.SecureRandom;

public class SecretGenerator {

    private final int size;

    public SecretGenerator(int size) {
        this.size = size;
    }

    public byte[] generate() {
        SecureRandom rng = new SecureRandom();
        byte[] secret = new byte[size];
        rng.nextBytes(secret);
        return secret;
    }
}
