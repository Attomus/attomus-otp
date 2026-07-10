package com.attomus.otp

object TOTP {
    fun generate(
        secret: ByteArray,
        clock: () -> Long = { System.currentTimeMillis() / 1000L },
        algorithm: OTPAlgorithm = OTPAlgorithm.SHA1,
        digits: Int = 6,
        period: Int = 30
    ): String {
        OTPValidation.validateTOTPSecret(secret)
        OTPValidation.validateTOTPDigits(digits)
        OTPValidation.validateTOTPPeriod(period)

        val nowSeconds = clock()
        if (nowSeconds < 0) {
            throw TOTPError.InvalidTime
        }
        val counter = Math.floorDiv(nowSeconds, period.toLong())
        return HOTP.generate(secret = secret, counter = counter, algorithm = algorithm, digits = digits)
    }

    fun remainingSeconds(
        clock: () -> Long = { System.currentTimeMillis() / 1000L },
        period: Int = 30
    ): Int {
        OTPValidation.validateTOTPPeriod(period)

        val nowSeconds = clock()
        if (nowSeconds < 0) {
            throw TOTPError.InvalidTime
        }
        val remainder = Math.floorMod(nowSeconds, period.toLong())
        return if (remainder == 0L) period else (period - remainder).toInt()
    }
}
