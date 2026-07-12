package com.attomus.otp

internal object OTPValidation {
    const val minimumSecretLength = 10
    const val maximumSecretLength = 64

    private val validDigits = setOf(6, 7, 8)
    private val validPeriods = setOf(30, 60)

    fun validateHOTPSecret(secret: ByteArray) {
        validateSecret(
            secret = secret,
            shortError = HOTPError.SecretTooShort,
            longError = HOTPError.SecretTooLong
        )
    }

    fun validateTOTPSecret(secret: ByteArray) {
        validateSecret(
            secret = secret,
            shortError = TOTPError.SecretTooShort,
            longError = TOTPError.SecretTooLong
        )
    }

    fun validateHOTPDigits(digits: Int) {
        if (digits !in validDigits) {
            throw HOTPError.InvalidDigitCount
        }
    }

    fun validateTOTPDigits(digits: Int) {
        if (digits !in validDigits) {
            throw TOTPError.InvalidDigitCount
        }
    }

    fun validateTOTPPeriod(period: Int) {
        if (period !in validPeriods) {
            throw TOTPError.InvalidPeriod
        }
    }

    fun validateURISecret(secret: ByteArray) {
        when {
            secret.size < minimumSecretLength -> throw OTPURIError.SecretTooShort
            secret.size > maximumSecretLength -> throw OTPURIError.SecretTooLong
        }
    }

    fun validateURIDigits(digits: Int) {
        if (digits !in validDigits) {
            throw OTPURIError.InvalidDigits
        }
    }

    fun validateURIPeriod(period: Int) {
        if (period !in validPeriods) {
            throw OTPURIError.InvalidPeriod
        }
    }

    @Suppress("ThrowsCount")
    private fun validateSecret(
        secret: ByteArray,
        shortError: Exception,
        longError: Exception
    ) {
        when {
            secret.isEmpty() -> throw shortError
            secret.size < minimumSecretLength -> throw shortError
            secret.size > maximumSecretLength -> throw longError
        }
    }
}
