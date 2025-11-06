package br.dev.webit.totp;

import java.util.stream.IntStream;

public class Verifier {

    private final Generator generator;
    private final int timeStep;
    private final int offset;

    /**
     * Creates a T-OTP verifier.
     * 
     * @param generator The T-OTP generator to be used to recreate the token.
     * @param timeStep  The amount of seconds a time-step used during the moving
     *                  factor computation has.
     * @param offset    Number of previous time-steps considered before failing the
     *                  verification.
     */
    public Verifier(Generator generator, int timeStep, int offset) {
        this.generator = generator;
        if ((this.timeStep = timeStep) <= 0) {
            throw new IllegalArgumentException();
        }
        if ((this.offset = offset) < 0) {
            throw new IllegalArgumentException();
        }
    }

    /**
     * Executes the verification.
     * 
     * @param secret The seed used to generate the token.
     * @param token  The token against which the verification occurs.
     * @param time   Number of seconds since Epoch.
     * @return {@code true} when {@code token} is valid for the provided {@code time} within the {@code offset} past timesteps.
     */
    public boolean verify(final byte[] secret, final String token, final long time) {
        final long movingFactor = time / timeStep;
        return IntStream.rangeClosed(0, -1 * offset)
                .anyMatch(i -> generator.generate(secret, movingFactor - i).equals(token));
    }
}
