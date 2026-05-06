package com.attomus.otp

import java.nio.charset.StandardCharsets

internal object TestSupport {
    fun asciiData(value: String): ByteArray = value.toByteArray(StandardCharsets.US_ASCII)

    fun repeatedData(count: Int, seed: Int = 0xAB): ByteArray {
        return ByteArray(count) { index -> (seed + index).toByte() }
    }
}

