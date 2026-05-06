package com.attomus.otp

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class HOTPTest {
    @Test
    fun rfc4226AppendixDTestVectors() {
        val secret = TestSupport.asciiData("12345678901234567890")
        val expected = listOf(
            "755224",
            "287082",
            "359152",
            "969429",
            "338314",
            "254676",
            "287922",
            "162583",
            "399871",
            "520489"
        )

        expected.forEachIndexed { counter, code ->
            assertEquals(code, HOTP.generate(secret = secret, counter = counter.toLong()))
        }
    }

    @Test
    fun supportsAllowedDigitCounts() {
        val secret = TestSupport.repeatedData(count = 20)
        assertEquals(6, HOTP.generate(secret, 1, digits = 6).length)
        assertEquals(7, HOTP.generate(secret, 1, digits = 7).length)
        assertEquals(8, HOTP.generate(secret, 1, digits = 8).length)
    }

    @Test
    fun rejectsShortSecret() {
        val error = assertThrows(HOTPError.SecretTooShort::class.java) {
            HOTP.generate(secret = byteArrayOf(0x00), counter = 0)
        }
        assertEquals(HOTPError.SecretTooShort, error)
    }

    @Test
    fun rejectsEmptySecret() {
        assertThrows(HOTPError.SecretTooShort::class.java) {
            HOTP.generate(secret = ByteArray(0), counter = 0)
        }
    }

    @Test
    fun rejectsLongSecret() {
        assertThrows(HOTPError.SecretTooLong::class.java) {
            HOTP.generate(secret = TestSupport.repeatedData(count = 65), counter = 0)
        }
    }

    @Test
    fun rejectsInvalidDigitCount() {
        assertThrows(HOTPError.InvalidDigitCount::class.java) {
            HOTP.generate(secret = TestSupport.repeatedData(count = 20), counter = 0, digits = 5)
        }
    }

    @Test
    fun supportsAlternateAlgorithms() {
        val secret = TestSupport.repeatedData(count = 32)
        assertEquals(8, HOTP.generate(secret = secret, counter = 42, algorithm = OTPAlgorithm.SHA256, digits = 8).length)
        assertEquals(8, HOTP.generate(secret = secret, counter = 42, algorithm = OTPAlgorithm.SHA512, digits = 8).length)
    }

    @Test
    fun supportsMaximumCounterBitPattern() {
        val secret = TestSupport.repeatedData(count = 20)
        assertEquals(6, HOTP.generate(secret = secret, counter = Long.MIN_VALUE).length)
    }
}

