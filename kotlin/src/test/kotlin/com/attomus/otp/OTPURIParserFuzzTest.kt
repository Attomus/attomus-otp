package com.attomus.otp

import com.code_intelligence.jazzer.api.FuzzedDataProvider
import com.code_intelligence.jazzer.junit.FuzzTest

class OTPURIParserFuzzTest {

    private val fuzzPeriods = intArrayOf(-1, 0, 1, 15, 30, 60, 90)

    @FuzzTest(maxDuration = "4h")
    fun fuzzParseURI(data: FuzzedDataProvider) {
        val input = data.consumeRemainingAsString()
        try {
            OTPURIParser.parse(input)
        } catch (e: Exception) {
            if (e !is OTPURIError) {
                throw e
            }
        }
    }

    @FuzzTest(maxDuration = "4h")
    @Suppress("SwallowedException")
    fun fuzzTotpTimeAndPeriodBoundaries(data: FuzzedDataProvider) {
        val input = data.consumeBytes(64)
        val secret = when {
            input.size >= 10 -> input
            input.isEmpty() -> ByteArray(10) { 0x41 }
            else -> ByteArray(10) { input[it % input.size] }
        }
        val period = fuzzPeriods[Math.floorMod(data.consumeInt(), fuzzPeriods.size)]
        val timestamp = data.consumeLong()

        try {
            TOTP.generate(secret = secret, clock = { timestamp }, period = period)
            TOTP.remainingSeconds(clock = { timestamp }, period = period)
        } catch (error: TOTPError) {
            // Invalid periods and pre-epoch timestamps are expected fuzz inputs.
        } finally {
            secret.fill(0)
        }
    }
}
