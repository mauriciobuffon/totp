package br.dev.webit.totp;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.stream.Stream;

import org.apache.commons.codec.binary.Base32;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class GeneratorUnitTest {

    private Base32 base32 = new Base32();

    @ParameterizedTest
    @MethodSource("provider")
    public void test(HashingAlgorithm algorithm, int size, long timestamp, String seed, String expectedOtp) {
        Generator generator = new Generator(algorithm, size);
        String otp = generator.generate(base32.decode(seed), timestamp / 30);
        assertEquals(expectedOtp, otp);
    }

    static Stream<Arguments> provider() {
        return Stream.<Arguments>of(
                Arguments.of(HashingAlgorithm.SHA1, 6, 59L, "GEMJ3BIKFABAS6QUCEGIXMYZWQ2KXEHT", "943183"),
                Arguments.of(HashingAlgorithm.SHA1, 7, 59L, "GEMJ3BIKFABAS6QUCEGIXMYZWQ2KXEHT", "9943183"),
                Arguments.of(HashingAlgorithm.SHA1, 8, 59L, "GEMJ3BIKFABAS6QUCEGIXMYZWQ2KXEHT", "69943183"),
                Arguments.of(HashingAlgorithm.SHA1, 9, 59L, "GEMJ3BIKFABAS6QUCEGIXMYZWQ2KXEHT", "169943183"),
                Arguments.of(HashingAlgorithm.SHA1, 6, 1111111109L, "GEMJ3BIKFABAS6QUCEGIXMYZWQ2KXEHT", "572664"),
                Arguments.of(HashingAlgorithm.SHA1, 7, 1111111109L, "GEMJ3BIKFABAS6QUCEGIXMYZWQ2KXEHT", "1572664"),
                Arguments.of(HashingAlgorithm.SHA1, 8, 1111111109L, "GEMJ3BIKFABAS6QUCEGIXMYZWQ2KXEHT", "71572664"),
                Arguments.of(HashingAlgorithm.SHA1, 9, 1111111109L, "GEMJ3BIKFABAS6QUCEGIXMYZWQ2KXEHT", "971572664"),
                Arguments.of(HashingAlgorithm.SHA1, 6, 1111111111L, "GEMJ3BIKFABAS6QUCEGIXMYZWQ2KXEHT", "302530"),
                Arguments.of(HashingAlgorithm.SHA1, 7, 1111111111L, "GEMJ3BIKFABAS6QUCEGIXMYZWQ2KXEHT", "5302530"),
                Arguments.of(HashingAlgorithm.SHA1, 8, 1111111111L, "GEMJ3BIKFABAS6QUCEGIXMYZWQ2KXEHT", "75302530"),
                Arguments.of(HashingAlgorithm.SHA1, 9, 1111111111L, "GEMJ3BIKFABAS6QUCEGIXMYZWQ2KXEHT", "675302530"),
                Arguments.of(HashingAlgorithm.SHA1, 6, 1234567890L, "GEMJ3BIKFABAS6QUCEGIXMYZWQ2KXEHT", "880183"),
                Arguments.of(HashingAlgorithm.SHA1, 7, 1234567890L, "GEMJ3BIKFABAS6QUCEGIXMYZWQ2KXEHT", "8880183"),
                Arguments.of(HashingAlgorithm.SHA1, 8, 1234567890L, "GEMJ3BIKFABAS6QUCEGIXMYZWQ2KXEHT", "48880183"),
                Arguments.of(HashingAlgorithm.SHA1, 9, 1234567890L, "GEMJ3BIKFABAS6QUCEGIXMYZWQ2KXEHT", "548880183"),
                Arguments.of(HashingAlgorithm.SHA1, 6, 2000000000L, "GEMJ3BIKFABAS6QUCEGIXMYZWQ2KXEHT", "357217"),
                Arguments.of(HashingAlgorithm.SHA1, 7, 2000000000L, "GEMJ3BIKFABAS6QUCEGIXMYZWQ2KXEHT", "0357217"),
                Arguments.of(HashingAlgorithm.SHA1, 8, 2000000000L, "GEMJ3BIKFABAS6QUCEGIXMYZWQ2KXEHT", "00357217"),
                Arguments.of(HashingAlgorithm.SHA1, 9, 2000000000L, "GEMJ3BIKFABAS6QUCEGIXMYZWQ2KXEHT", "500357217"),
                Arguments.of(HashingAlgorithm.SHA1, 6, 20000000000L, "GEMJ3BIKFABAS6QUCEGIXMYZWQ2KXEHT", "362733"),
                Arguments.of(HashingAlgorithm.SHA1, 7, 20000000000L, "GEMJ3BIKFABAS6QUCEGIXMYZWQ2KXEHT", "8362733"),
                Arguments.of(HashingAlgorithm.SHA1, 8, 20000000000L, "GEMJ3BIKFABAS6QUCEGIXMYZWQ2KXEHT", "58362733"),
                Arguments.of(HashingAlgorithm.SHA1, 9, 20000000000L, "GEMJ3BIKFABAS6QUCEGIXMYZWQ2KXEHT", "758362733"),
                Arguments.of(HashingAlgorithm.SHA1, 6, 59L, "SHGZMYOKDNXQZAPSHMR2FJWO7QZTTFGI", "706222"),
                Arguments.of(HashingAlgorithm.SHA1, 7, 59L, "SHGZMYOKDNXQZAPSHMR2FJWO7QZTTFGI", "6706222"),
                Arguments.of(HashingAlgorithm.SHA1, 8, 59L, "SHGZMYOKDNXQZAPSHMR2FJWO7QZTTFGI", "36706222"),
                Arguments.of(HashingAlgorithm.SHA1, 9, 59L, "SHGZMYOKDNXQZAPSHMR2FJWO7QZTTFGI", "536706222"),
                Arguments.of(HashingAlgorithm.SHA1, 6, 1111111109L, "SHGZMYOKDNXQZAPSHMR2FJWO7QZTTFGI", "434096"),
                Arguments.of(HashingAlgorithm.SHA1, 7, 1111111109L, "SHGZMYOKDNXQZAPSHMR2FJWO7QZTTFGI", "1434096"),
                Arguments.of(HashingAlgorithm.SHA1, 8, 1111111109L, "SHGZMYOKDNXQZAPSHMR2FJWO7QZTTFGI", "71434096"),
                Arguments.of(HashingAlgorithm.SHA1, 9, 1111111109L, "SHGZMYOKDNXQZAPSHMR2FJWO7QZTTFGI", "171434096"),
                Arguments.of(HashingAlgorithm.SHA1, 6, 1111111111L, "SHGZMYOKDNXQZAPSHMR2FJWO7QZTTFGI", "571526"),
                Arguments.of(HashingAlgorithm.SHA1, 7, 1111111111L, "SHGZMYOKDNXQZAPSHMR2FJWO7QZTTFGI", "1571526"),
                Arguments.of(HashingAlgorithm.SHA1, 8, 1111111111L, "SHGZMYOKDNXQZAPSHMR2FJWO7QZTTFGI", "41571526"),
                Arguments.of(HashingAlgorithm.SHA1, 9, 1111111111L, "SHGZMYOKDNXQZAPSHMR2FJWO7QZTTFGI", "641571526"),
                Arguments.of(HashingAlgorithm.SHA1, 6, 1234567890L, "SHGZMYOKDNXQZAPSHMR2FJWO7QZTTFGI", "719067"),
                Arguments.of(HashingAlgorithm.SHA1, 7, 1234567890L, "SHGZMYOKDNXQZAPSHMR2FJWO7QZTTFGI", "0719067"),
                Arguments.of(HashingAlgorithm.SHA1, 8, 1234567890L, "SHGZMYOKDNXQZAPSHMR2FJWO7QZTTFGI", "50719067"),
                Arguments.of(HashingAlgorithm.SHA1, 9, 1234567890L, "SHGZMYOKDNXQZAPSHMR2FJWO7QZTTFGI", "850719067"),
                Arguments.of(HashingAlgorithm.SHA1, 6, 2000000000L, "SHGZMYOKDNXQZAPSHMR2FJWO7QZTTFGI", "479228"),
                Arguments.of(HashingAlgorithm.SHA1, 7, 2000000000L, "SHGZMYOKDNXQZAPSHMR2FJWO7QZTTFGI", "8479228"),
                Arguments.of(HashingAlgorithm.SHA1, 8, 2000000000L, "SHGZMYOKDNXQZAPSHMR2FJWO7QZTTFGI", "58479228"),
                Arguments.of(HashingAlgorithm.SHA1, 9, 2000000000L, "SHGZMYOKDNXQZAPSHMR2FJWO7QZTTFGI", "158479228"),
                Arguments.of(HashingAlgorithm.SHA1, 6, 20000000000L, "SHGZMYOKDNXQZAPSHMR2FJWO7QZTTFGI", "869142"),
                Arguments.of(HashingAlgorithm.SHA1, 7, 20000000000L, "SHGZMYOKDNXQZAPSHMR2FJWO7QZTTFGI", "7869142"),
                Arguments.of(HashingAlgorithm.SHA1, 8, 20000000000L, "SHGZMYOKDNXQZAPSHMR2FJWO7QZTTFGI", "17869142"),
                Arguments.of(HashingAlgorithm.SHA1, 9, 20000000000L, "SHGZMYOKDNXQZAPSHMR2FJWO7QZTTFGI", "217869142"),
                Arguments.of(HashingAlgorithm.SHA1, 6, 59L, "QMYULGHG3OMNYBCFBSXFI3SLN7XYQNJQ", "302198"),
                Arguments.of(HashingAlgorithm.SHA1, 7, 59L, "QMYULGHG3OMNYBCFBSXFI3SLN7XYQNJQ", "8302198"),
                Arguments.of(HashingAlgorithm.SHA1, 8, 59L, "QMYULGHG3OMNYBCFBSXFI3SLN7XYQNJQ", "88302198"),
                Arguments.of(HashingAlgorithm.SHA1, 9, 59L, "QMYULGHG3OMNYBCFBSXFI3SLN7XYQNJQ", "388302198"),
                Arguments.of(HashingAlgorithm.SHA1, 6, 1111111109L, "QMYULGHG3OMNYBCFBSXFI3SLN7XYQNJQ", "776788"),
                Arguments.of(HashingAlgorithm.SHA1, 7, 1111111109L, "QMYULGHG3OMNYBCFBSXFI3SLN7XYQNJQ", "1776788"),
                Arguments.of(HashingAlgorithm.SHA1, 8, 1111111109L, "QMYULGHG3OMNYBCFBSXFI3SLN7XYQNJQ", "11776788"),
                Arguments.of(HashingAlgorithm.SHA1, 9, 1111111109L, "QMYULGHG3OMNYBCFBSXFI3SLN7XYQNJQ", "111776788"),
                Arguments.of(HashingAlgorithm.SHA1, 6, 1111111111L, "QMYULGHG3OMNYBCFBSXFI3SLN7XYQNJQ", "368640"),
                Arguments.of(HashingAlgorithm.SHA1, 7, 1111111111L, "QMYULGHG3OMNYBCFBSXFI3SLN7XYQNJQ", "8368640"),
                Arguments.of(HashingAlgorithm.SHA1, 8, 1111111111L, "QMYULGHG3OMNYBCFBSXFI3SLN7XYQNJQ", "58368640"),
                Arguments.of(HashingAlgorithm.SHA1, 9, 1111111111L, "QMYULGHG3OMNYBCFBSXFI3SLN7XYQNJQ", "758368640"),
                Arguments.of(HashingAlgorithm.SHA1, 6, 1234567890L, "QMYULGHG3OMNYBCFBSXFI3SLN7XYQNJQ", "784208"),
                Arguments.of(HashingAlgorithm.SHA1, 7, 1234567890L, "QMYULGHG3OMNYBCFBSXFI3SLN7XYQNJQ", "5784208"),
                Arguments.of(HashingAlgorithm.SHA1, 8, 1234567890L, "QMYULGHG3OMNYBCFBSXFI3SLN7XYQNJQ", "35784208"),
                Arguments.of(HashingAlgorithm.SHA1, 9, 1234567890L, "QMYULGHG3OMNYBCFBSXFI3SLN7XYQNJQ", "735784208"),
                Arguments.of(HashingAlgorithm.SHA1, 6, 2000000000L, "QMYULGHG3OMNYBCFBSXFI3SLN7XYQNJQ", "748119"),
                Arguments.of(HashingAlgorithm.SHA1, 7, 2000000000L, "QMYULGHG3OMNYBCFBSXFI3SLN7XYQNJQ", "3748119"),
                Arguments.of(HashingAlgorithm.SHA1, 8, 2000000000L, "QMYULGHG3OMNYBCFBSXFI3SLN7XYQNJQ", "43748119"),
                Arguments.of(HashingAlgorithm.SHA1, 9, 2000000000L, "QMYULGHG3OMNYBCFBSXFI3SLN7XYQNJQ", "143748119"),
                Arguments.of(HashingAlgorithm.SHA1, 6, 20000000000L, "QMYULGHG3OMNYBCFBSXFI3SLN7XYQNJQ", "920855"),
                Arguments.of(HashingAlgorithm.SHA1, 7, 20000000000L, "QMYULGHG3OMNYBCFBSXFI3SLN7XYQNJQ", "9920855"),
                Arguments.of(HashingAlgorithm.SHA1, 8, 20000000000L, "QMYULGHG3OMNYBCFBSXFI3SLN7XYQNJQ", "09920855"),
                Arguments.of(HashingAlgorithm.SHA1, 9, 20000000000L, "QMYULGHG3OMNYBCFBSXFI3SLN7XYQNJQ", "809920855"),
                Arguments.of(HashingAlgorithm.SHA1, 6, 59L, "VTMAWBYVD5KUEQZB667ISH7EX7WH244X", "954424"),
                Arguments.of(HashingAlgorithm.SHA1, 7, 59L, "VTMAWBYVD5KUEQZB667ISH7EX7WH244X", "2954424"),
                Arguments.of(HashingAlgorithm.SHA1, 8, 59L, "VTMAWBYVD5KUEQZB667ISH7EX7WH244X", "72954424"),
                Arguments.of(HashingAlgorithm.SHA1, 9, 59L, "VTMAWBYVD5KUEQZB667ISH7EX7WH244X", "772954424"),
                Arguments.of(HashingAlgorithm.SHA1, 6, 1111111109L, "VTMAWBYVD5KUEQZB667ISH7EX7WH244X", "497565"),
                Arguments.of(HashingAlgorithm.SHA1, 7, 1111111109L, "VTMAWBYVD5KUEQZB667ISH7EX7WH244X", "4497565"),
                Arguments.of(HashingAlgorithm.SHA1, 8, 1111111109L, "VTMAWBYVD5KUEQZB667ISH7EX7WH244X", "74497565"),
                Arguments.of(HashingAlgorithm.SHA1, 9, 1111111109L, "VTMAWBYVD5KUEQZB667ISH7EX7WH244X", "674497565"),
                Arguments.of(HashingAlgorithm.SHA1, 6, 1111111111L, "VTMAWBYVD5KUEQZB667ISH7EX7WH244X", "180845"),
                Arguments.of(HashingAlgorithm.SHA1, 7, 1111111111L, "VTMAWBYVD5KUEQZB667ISH7EX7WH244X", "3180845"),
                Arguments.of(HashingAlgorithm.SHA1, 8, 1111111111L, "VTMAWBYVD5KUEQZB667ISH7EX7WH244X", "13180845"),
                Arguments.of(HashingAlgorithm.SHA1, 9, 1111111111L, "VTMAWBYVD5KUEQZB667ISH7EX7WH244X", "513180845"),
                Arguments.of(HashingAlgorithm.SHA1, 6, 1234567890L, "VTMAWBYVD5KUEQZB667ISH7EX7WH244X", "981175"),
                Arguments.of(HashingAlgorithm.SHA1, 7, 1234567890L, "VTMAWBYVD5KUEQZB667ISH7EX7WH244X", "1981175"),
                Arguments.of(HashingAlgorithm.SHA1, 8, 1234567890L, "VTMAWBYVD5KUEQZB667ISH7EX7WH244X", "91981175"),
                Arguments.of(HashingAlgorithm.SHA1, 9, 1234567890L, "VTMAWBYVD5KUEQZB667ISH7EX7WH244X", "291981175"),
                Arguments.of(HashingAlgorithm.SHA1, 6, 2000000000L, "VTMAWBYVD5KUEQZB667ISH7EX7WH244X", "074137"),
                Arguments.of(HashingAlgorithm.SHA1, 7, 2000000000L, "VTMAWBYVD5KUEQZB667ISH7EX7WH244X", "5074137"),
                Arguments.of(HashingAlgorithm.SHA1, 8, 2000000000L, "VTMAWBYVD5KUEQZB667ISH7EX7WH244X", "15074137"),
                Arguments.of(HashingAlgorithm.SHA1, 9, 2000000000L, "VTMAWBYVD5KUEQZB667ISH7EX7WH244X", "615074137"),
                Arguments.of(HashingAlgorithm.SHA1, 6, 20000000000L, "VTMAWBYVD5KUEQZB667ISH7EX7WH244X", "007106"),
                Arguments.of(HashingAlgorithm.SHA1, 7, 20000000000L, "VTMAWBYVD5KUEQZB667ISH7EX7WH244X", "8007106"),
                Arguments.of(HashingAlgorithm.SHA1, 8, 20000000000L, "VTMAWBYVD5KUEQZB667ISH7EX7WH244X", "88007106"),
                Arguments.of(HashingAlgorithm.SHA1, 9, 20000000000L, "VTMAWBYVD5KUEQZB667ISH7EX7WH244X", "488007106"));
    }
}
