package com.attomus.otp

import com.code_intelligence.jazzer.api.FuzzedDataProvider
import com.code_intelligence.jazzer.junit.FuzzTest

class OTPURIParserFuzzTest {

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
}
