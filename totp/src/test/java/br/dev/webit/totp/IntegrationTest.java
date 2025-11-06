package br.dev.webit.totp;

import org.apache.commons.codec.binary.Base32;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class IntegrationTest {

    @ParameterizedTest
    @ValueSource(strings = { "GEMJ3BIKFABAS6QUCEGIXMYZWQ2KXEHT", "SHGZMYOKDNXQZAPSHMR2FJWO7QZTTFGI",
            "QMYULGHG3OMNYBCFBSXFI3SLN7XYQNJQ", "VTMAWBYVD5KUEQZB667ISH7EX7WH244X", "I65VU7K5ZQL7WB4E" })
    public void generatorTest(String seed) {
        final int timeStepSize = 30;
        final Base32 base32 = new Base32();
        Generator generator = new Generator(HashingAlgorithm.SHA1, 6);
        final long secondsSinceEpoch = System.currentTimeMillis() / 1_000;
        final var movingFactor = secondsSinceEpoch / timeStepSize;
        String otp = generator.generate(base32.decode(seed), movingFactor);

        // TODO: improve this test

        System.out.println(otp);
    }

    public void verifierTest() {
    }
}
