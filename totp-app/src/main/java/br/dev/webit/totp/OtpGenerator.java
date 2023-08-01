package br.dev.webit.totp;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class OtpGenerator {

    private final String algorithm;
    private final int size;

    public OtpGenerator(HashingAlgorithm algorithm, int size) {
        if (null == algorithm) {
            throw new IllegalArgumentException();
        }
        this.algorithm = algorithm.getAlgorithm();

        if (size < 6) {
            throw new IllegalArgumentException();
        }
        this.size = size;
    }

    public String generate(final byte[] secret, final long movingFactor) throws OtpGenerationException {
        final byte[] hash;

        try {
            final byte[] text = ByteBuffer.allocate(Long.BYTES).putLong(movingFactor).array();
            Mac mac = Mac.getInstance(algorithm);
            SecretKey key = new SecretKeySpec(secret, algorithm);
            mac.init(key);
            hash = mac.doFinal(text);
        } catch (InvalidKeyException | NoSuchAlgorithmException ex) {
            throw new OtpGenerationException(ex);
        }

        final int offset = hash[hash.length - 1] & 0xf;

        final int binary = ((hash[offset] & 0x7f) << 24)
                | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8)
                | (hash[offset + 3] & 0xff);

        final int otp = binary % (int) Math.pow(10, size);

        return "%".concat("0".repeat(size)).concat("d").formatted(otp);
    }
}
