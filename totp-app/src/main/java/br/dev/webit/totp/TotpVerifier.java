package br.dev.webit.totp;

public class TotpVerifier {

    private final OtpGenerator generator;
    private final int timeStepSize;
    private final int timeStepOffset;

    public TotpVerifier(OtpGenerator generator, int timeStepSize, int timeStepOffset) {
        this.generator = generator;
        this.timeStepSize = timeStepSize;
        this.timeStepOffset = timeStepOffset;
    }

    public boolean verify(final byte[] secret, final String otp, final long time) {
        final long timeStep = time / timeStepSize;

        boolean flag = false;
        for (int i = 0; i < timeStepOffset; i++) {
            flag = flag || generator.generate(secret, timeStep - i).equals(otp);
        }

        return flag;
    }
}
