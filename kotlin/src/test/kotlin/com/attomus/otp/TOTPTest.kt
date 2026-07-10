package com.attomus.otp

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class TOTPTest {
    @Test
    fun rfc6238AppendixB_sha1() {
        assertVectors(
            secret = TestSupport.asciiData("12345678901234567890"),
            algorithm = OTPAlgorithm.SHA1,
            expected = listOf(
                59L to "94287082",
                1111111109L to "07081804",
                1111111111L to "14050471",
                1234567890L to "89005924",
                2000000000L to "69279037",
                20000000000L to "65353130"
            )
        )
    }

    @Test
    fun rfc6238AppendixB_sha256() {
        assertVectors(
            secret = TestSupport.asciiData("12345678901234567890123456789012"),
            algorithm = OTPAlgorithm.SHA256,
            expected = listOf(
                59L to "46119246",
                1111111109L to "68084774",
                1111111111L to "67062674",
                1234567890L to "91819424",
                2000000000L to "90698825",
                20000000000L to "77737706"
            )
        )
    }

    @Test
    fun rfc6238AppendixB_sha512() {
        assertVectors(
            secret = TestSupport.asciiData("1234567890123456789012345678901234567890123456789012345678901234"),
            algorithm = OTPAlgorithm.SHA512,
            expected = listOf(
                59L to "90693936",
                1111111109L to "25091201",
                1111111111L to "99943326",
                1234567890L to "93441116",
                2000000000L to "38618901",
                20000000000L to "47863826"
            )
        )
    }

    @Test
    fun supportsAllowedDigitCounts() {
        val secret = TestSupport.repeatedData(count = 20)
        val clock = { 1_234_567_890L }
        assertEquals(6, TOTP.generate(secret = secret, clock = clock, digits = 6).length)
        assertEquals(7, TOTP.generate(secret = secret, clock = clock, digits = 7).length)
        assertEquals(8, TOTP.generate(secret = secret, clock = clock, digits = 8).length)
    }

    @Test
    fun supportsSixtySecondPeriod() {
        val secret = TestSupport.repeatedData(count = 20)
        val clock = { 120L }
        assertEquals(6, TOTP.generate(secret = secret, clock = clock, period = 60).length)
        assertEquals(60, TOTP.remainingSeconds(clock = clock, period = 60))
    }

    @Test
    fun rejectsInvalidDigitCount() {
        assertThrows(TOTPError.InvalidDigitCount::class.java) {
            TOTP.generate(secret = TestSupport.repeatedData(count = 20), clock = { 0L }, digits = 9)
        }
    }

    @Test
    fun rejectsInvalidPeriod() {
        assertThrows(TOTPError.InvalidPeriod::class.java) {
            TOTP.generate(secret = TestSupport.repeatedData(count = 20), clock = { 0L }, period = 45)
        }
        assertThrows(TOTPError.InvalidPeriod::class.java) {
            TOTP.remainingSeconds(clock = { 0L }, period = 0)
        }
    }

    @Test
    fun rejectsPreEpochTimes() {
        val secret = TestSupport.repeatedData(count = 20)
        listOf(-1L, -86_400L, -30L).forEach { timestamp ->
            assertThrows(TOTPError.InvalidTime::class.java) {
                TOTP.generate(secret = secret, clock = { timestamp })
            }
            assertThrows(TOTPError.InvalidTime::class.java) {
                TOTP.remainingSeconds(clock = { timestamp })
            }
        }
    }

    @Test
    fun rejectsShortSecret() {
        assertThrows(TOTPError.SecretTooShort::class.java) {
            TOTP.generate(secret = byteArrayOf(0x01), clock = { 0L })
        }
    }

    @Test
    fun rejectsEmptySecret() {
        assertThrows(TOTPError.SecretTooShort::class.java) {
            TOTP.generate(secret = ByteArray(0), clock = { 0L })
        }
    }

    private fun assertVectors(
        secret: ByteArray,
        algorithm: OTPAlgorithm,
        expected: List<Pair<Long, String>>
    ) {
        expected.forEach { (timestamp, code) ->
            assertEquals(
                code,
                TOTP.generate(
                    secret = secret,
                    clock = { timestamp },
                    algorithm = algorithm,
                    digits = 8,
                    period = 30
                )
            )
        }
    }
}
