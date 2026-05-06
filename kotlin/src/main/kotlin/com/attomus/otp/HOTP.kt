package com.attomus.otp

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object HOTP {
    fun generate(
        secret: ByteArray,
        counter: Long,
        algorithm: OTPAlgorithm = OTPAlgorithm.SHA1,
        digits: Int = 6
    ): String {
        OTPValidation.validateHOTPSecret(secret)
        OTPValidation.validateHOTPDigits(digits)

        val counterBytes = counter.toBigEndianBytes()
        var hmac: ByteArray? = null

        try {
            hmac = authenticationCode(counterBytes, secret, algorithm)
            val truncated = truncate(hmac)
            val modulus = modulusForDigits(digits)
            val code = truncated % modulus
            return code.toString().padStart(digits, '0')
        } finally {
            counterBytes.zero()
            hmac?.zero()
        }
    }

    private fun authenticationCode(
        counterBytes: ByteArray,
        secret: ByteArray,
        algorithm: OTPAlgorithm
    ): ByteArray {
        val macAlgorithm = when (algorithm) {
            OTPAlgorithm.SHA1 -> "HmacSHA1"
            OTPAlgorithm.SHA256 -> "HmacSHA256"
            OTPAlgorithm.SHA512 -> "HmacSHA512"
        }

        val mac = Mac.getInstance(macAlgorithm)
        mac.init(SecretKeySpec(secret, macAlgorithm))
        return mac.doFinal(counterBytes)
    }

    private fun truncate(hmac: ByteArray): Long {
        val offset = hmac[hmac.lastIndex].toInt() and 0x0f
        val part0 = (hmac[offset].toInt() and 0x7f) shl 24
        val part1 = (hmac[offset + 1].toInt() and 0xff) shl 16
        val part2 = (hmac[offset + 2].toInt() and 0xff) shl 8
        val part3 = hmac[offset + 3].toInt() and 0xff
        return (part0 or part1 or part2 or part3).toLong()
    }

    private fun modulusForDigits(digits: Int): Long {
        return when (digits) {
            6 -> 1_000_000L
            7 -> 10_000_000L
            8 -> 100_000_000L
            else -> error("Unexpected digit count")
        }
    }

    private fun Long.toBigEndianBytes(): ByteArray {
        val bytes = ByteArray(8)
        var value = this
        for (index in 7 downTo 0) {
            bytes[index] = (value and 0xffL).toByte()
            value = value ushr 8
        }
        return bytes
    }

    private fun ByteArray.zero() {
        fill(0)
    }
}

