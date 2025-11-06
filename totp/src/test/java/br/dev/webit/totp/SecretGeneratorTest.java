package br.dev.webit.totp;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class SecretGeneratorTest {

    @ParameterizedTest
    @ValueSource(ints = { 16, 20, 32 })
    public void secretSizeTest(int size) {
        SecretGenerator generator = new SecretGenerator(size);
        byte[] secret = generator.generate();
        assertEquals(size, secret.length);
    }
}
