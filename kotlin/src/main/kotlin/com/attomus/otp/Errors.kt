package com.attomus.otp

sealed class TOTPError(message: String? = null) : Exception(message) {
    object InvalidSecret : TOTPError()
    object InvalidDigitCount : TOTPError()
    object InvalidAlgorithm : TOTPError()
    object InvalidPeriod : TOTPError()
    object InvalidTime : TOTPError()
    object SecretTooShort : TOTPError()
    object SecretTooLong : TOTPError()
}

sealed class HOTPError(message: String? = null) : Exception(message) {
    object InvalidSecret : HOTPError()
    object InvalidDigitCount : HOTPError()
    object InvalidAlgorithm : HOTPError()
    object SecretTooShort : HOTPError()
    object SecretTooLong : HOTPError()
}

sealed class Base32Error(message: String? = null) : Exception(message) {
    object EmptyInput : Base32Error()
    data class InvalidCharacter(val character: Char) : Base32Error()
    object InvalidPadding : Base32Error()
}

sealed class OTPURIError(message: String? = null) : Exception(message) {
    object UriTooLong : OTPURIError()
    object InvalidScheme : OTPURIError()
    object InvalidType : OTPURIError()
    object MissingLabel : OTPURIError()
    object MissingSecret : OTPURIError()
    object InvalidSecret : OTPURIError()
    object SecretTooShort : OTPURIError()
    object SecretTooLong : OTPURIError()
    object InvalidAlgorithm : OTPURIError()
    object InvalidDigits : OTPURIError()
    object InvalidPeriod : OTPURIError()
    object MissingCounter : OTPURIError()
    object IssuerMismatch : OTPURIError()
    object MalformedPercentEncoding : OTPURIError()
}
