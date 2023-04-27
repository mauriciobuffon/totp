package br.dev.webit.totp;

import java.time.Instant;

import org.apache.commons.codec.binary.Base32;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class ToptGenerationTest {

    @ParameterizedTest
    @ValueSource(strings = { "GEMJ3BIKFABAS6QUCEGIXMYZWQ2KXEHT", "SHGZMYOKDNXQZAPSHMR2FJWO7QZTTFGI",
            "QMYULGHG3OMNYBCFBSXFI3SLN7XYQNJQ", "VTMAWBYVD5KUEQZB667ISH7EX7WH244X", "I65VU7K5ZQL7WB4E" })
    public void test(String seed) {
        final Base32 base32 = new Base32();
        OtpGenerator otpGenerator = new OtpGenerator(HashingAlgorithm.SHA1, 6);
        TotpVerifier totpVerifier = new TotpVerifier(otpGenerator, 30, 0);
        final long time = Instant.now().getEpochSecond();

        String otp = otpGenerator.generate(base32.decode(seed), time / 30);

        // TODO: improve this test

        System.out.println(otp);
    }
}
