package com.attomus.otp

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class OTPURIParserTest {
    @Test
    fun validUriExamples() {
        val longSecret = "IFBEGRCFIZDUQSKKJNGE2TSPKBIVEU2U"
        val alternateSecret = "ABCDEFGHIJKLMNOPQRSTUVWX23456723"
        val validCases: List<Triple<String, OTPType, String>> = listOf(
            Triple("otpauth://totp/Example:alice@example.com?secret=$longSecret&issuer=Example", OTPType.TOTP, "alice@example.com"),
            Triple("otpauth://totp/alice@example.com?secret=$longSecret&issuer=Example", OTPType.TOTP, "alice@example.com"),
            Triple("otpauth://totp/Example%20Corp:alice@example.com?secret=$longSecret&issuer=Example%20Corp", OTPType.TOTP, "alice@example.com"),
            Triple("otpauth://totp/Example:alice@example.com?secret=${longSecret.lowercase()}", OTPType.TOTP, "alice@example.com"),
            Triple("otpauth://totp/Example:alice@example.com?secret=IFBE%20GRCF%20IZDU%20QSKK%20JNGE%202TSP%20KBIV%20EU2U&issuer=Example", OTPType.TOTP, "alice@example.com"),
            Triple("otpauth://totp/Example:alice@example.com?secret=$longSecret&algorithm=SHA256&digits=7&issuer=Example", OTPType.TOTP, "alice@example.com"),
            Triple("otpauth://totp/Example:alice@example.com?secret=$longSecret&algorithm=SHA512&digits=8&issuer=Example", OTPType.TOTP, "alice@example.com"),
            Triple("otpauth://totp/Example:alice@example.com?secret=$longSecret&period=60&issuer=Example", OTPType.TOTP, "alice@example.com"),
            Triple("otpauth://totp/Example%3Aalice@example.com?secret=$longSecret&issuer=Example", OTPType.TOTP, "alice@example.com"),
            Triple("otpauth://totp/Example:%20alice@example.com?secret=$longSecret&issuer=Example", OTPType.TOTP, "alice@example.com"),
            Triple("otpauth://hotp/Example:alice@example.com?secret=$longSecret&issuer=Example&counter=0", OTPType.HOTP, "alice@example.com"),
            Triple("otpauth://hotp/Example:alice@example.com?secret=$longSecret&counter=9223372036854775807&issuer=Example", OTPType.HOTP, "alice@example.com"),
            Triple("otpauth://hotp/alice@example.com?secret=$longSecret&counter=42&issuer=Example", OTPType.HOTP, "alice@example.com"),
            Triple("otpauth://totp/alice@example.com?secret=$longSecret", OTPType.TOTP, "alice@example.com"),
            Triple("otpauth://totp/Example:alice@example.com?secret=$alternateSecret&issuer=Example", OTPType.TOTP, "alice@example.com"),
            Triple("otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30", OTPType.TOTP, "john.doe@email.com"),
            Triple("otpauth://totp/Big%20Team:ops@example.com?secret=$alternateSecret&issuer=Big%20Team", OTPType.TOTP, "ops@example.com"),
            Triple("otpauth://totp/issuer-only?secret=$longSecret&issuer=Example&unknown=value", OTPType.TOTP, "issuer-only"),
            Triple("otpauth://totp/Provider1:Alice%20Smith?secret=$longSecret&issuer=Provider1", OTPType.TOTP, "Alice Smith"),
            Triple("otpauth://totp/Provider1:Alice%20Smith?secret=$longSecret&issuer=Provider1&algorithm=sha1", OTPType.TOTP, "Alice Smith"),
            Triple("otpauth://totp/Provider1:Alice%20Smith?secret=$longSecret&issuer=Provider1&algorithm=sha256", OTPType.TOTP, "Alice Smith"),
            Triple("otpauth://totp/Provider1:Alice%20Smith?secret=$longSecret&issuer=Provider1&algorithm=sha512", OTPType.TOTP, "Alice Smith"),
            Triple("otpauth://totp/team@example.com?secret=$longSecret&digits=7", OTPType.TOTP, "team@example.com"),
            Triple("otpauth://totp/team@example.com?secret=$longSecret&digits=8", OTPType.TOTP, "team@example.com"),
            Triple("otpauth://totp/Example:alice@example.com?secret=$longSecret&issuer=Example", OTPType.TOTP, "alice@example.com"),
            Triple("otpauth://hotp/Example:alice@example.com?secret=$longSecret&issuer=Example&counter=1", OTPType.HOTP, "alice@example.com"),
            Triple("otpauth://totp/Example%20Security:alice%2Bprod@example.com?secret=$longSecret&issuer=Example%20Security", OTPType.TOTP, "alice+prod@example.com"),
            Triple("otpauth://totp/AccountOnly?secret=$alternateSecret", OTPType.TOTP, "AccountOnly"),
            Triple("otpauth://totp/Example:account?secret=$alternateSecret&issuer=Example&image=https%3A%2F%2Fexample.com%2Ficon.png", OTPType.TOTP, "account"),
            Triple("otpauth://totp/Label%20With%20Spaces?secret=$alternateSecret", OTPType.TOTP, "Label With Spaces"),
            Triple("otpauth://totp/Example:alice@example.com?secret=$longSecret&issuer=%20", OTPType.TOTP, "alice@example.com"),
            Triple("otpauth://totp/Example:alice@example.com?secret=$longSecret&algorithm=&digits=&period=", OTPType.TOTP, "alice@example.com"),
            Triple("otpauth://totp/GitHub:attomus-gh?secret=GM7VCK5SIAXEN46J&issuer=GitHub", OTPType.TOTP, "attomus-gh")
        )

        assertTrue(validCases.size >= 30)

        validCases.forEach { (uri, expectedType, expectedLabel) ->
            val result = OTPURIParser.parse(uri)
            assertEquals(expectedType, result.account.type)
            assertEquals(expectedLabel, result.account.label)
            assertTrue(result.secret.size >= 10)
        }
    }

    @Test
    fun invalidUriExamples() {
        val longSecret = "IFBEGRCFIZDUQSKKJNGE2TSPKBIVEU2U"
        val invalidCases: List<Pair<String, OTPURIError>> = listOf(
            StringBuilder().apply { repeat(2049) { append('a') } }.toString() to OTPURIError.UriTooLong,
            "https://totp/Example:alice@example.com?secret=$longSecret" to OTPURIError.InvalidScheme,
            "otpauth://steam/Example:alice@example.com?secret=$longSecret" to OTPURIError.InvalidType,
            "otpauth://totp/Example:alice@example.com" to OTPURIError.MissingSecret,
            "otpauth://totp/?secret=$longSecret" to OTPURIError.MissingLabel,
            "otpauth://totp/Example:alice@example.com?secret=JBSWY3D!" to OTPURIError.InvalidSecret,
            "otpauth://totp/Example:alice@example.com?secret=JBSWY3DP" to OTPURIError.SecretTooShort,
            "otpauth://totp/Example:alice@example.com?secret=${"A".repeat(104)}" to OTPURIError.SecretTooLong,
            "otpauth://totp/Example:alice@example.com?secret=$longSecret&digits=5" to OTPURIError.InvalidDigits,
            "otpauth://totp/Example:alice@example.com?secret=$longSecret&digits=9" to OTPURIError.InvalidDigits,
            "otpauth://totp/Example:alice@example.com?secret=$longSecret&digits=abc" to OTPURIError.InvalidDigits,
            "otpauth://totp/Example:alice@example.com?secret=$longSecret&period=45" to OTPURIError.InvalidPeriod,
            "otpauth://totp/Example:alice@example.com?secret=$longSecret&period=abc" to OTPURIError.InvalidPeriod,
            "otpauth://hotp/Example:alice@example.com?secret=$longSecret" to OTPURIError.MissingCounter,
            "otpauth://hotp/Example:alice@example.com?secret=$longSecret&counter=-1" to OTPURIError.MissingCounter,
            "otpauth://hotp/Example:alice@example.com?secret=$longSecret&counter=abc" to OTPURIError.MissingCounter,
            "otpauth://hotp/Example:alice@example.com?secret=$longSecret&counter=9223372036854775808" to OTPURIError.MissingCounter,
            "otpauth://hotp/Example:alice@example.com?secret=$longSecret&counter=18446744073709551615" to OTPURIError.MissingCounter,
            "otpauth://hotp/Example:alice@example.com?secret=$longSecret&counter=18446744073709551616" to OTPURIError.MissingCounter,
            "otpauth://totp/Example:alice@example.com?secret=$longSecret&issuer=Different" to OTPURIError.IssuerMismatch,
            "otpauth://totp/Example:%ZZalice@example.com?secret=$longSecret" to OTPURIError.MalformedPercentEncoding,
            "otpauth://totp/Example:alice@example.com?secret=$longSecret&algorithm=MD5" to OTPURIError.InvalidAlgorithm,
            "otpauth://totp/%?secret=$longSecret" to OTPURIError.MalformedPercentEncoding,
            "otpauth:///Example:alice@example.com?secret=$longSecret" to OTPURIError.InvalidType,
            "otpauth://totp/Example:alice@example.com?secret=$longSecret%" to OTPURIError.MalformedPercentEncoding,
            "otpauth://totp/Example:alice@example.com?secret=$longSecret%A" to OTPURIError.MalformedPercentEncoding,
            "otpauth://totp/%C3%28?secret=$longSecret" to OTPURIError.MalformedPercentEncoding,
            "otpauth://totp/Example:?secret=$longSecret" to OTPURIError.MissingLabel
        )

        assertTrue(invalidCases.size >= 20)

        invalidCases.forEach { (uri, expectedError) ->
            val error = assertThrows(expectedError::class.java) {
                OTPURIParser.parse(uri)
            }
            assertEquals(expectedError, error)
        }
    }

    @Test
    fun hotpUriCounterIsPreservedInAccount() {
        val result = OTPURIParser.parse("otpauth://hotp/Example:alice@example.com?secret=IFBEGRCFIZDUQSKKJNGE2TSPKBIVEU2U&issuer=Example&counter=42")
        assertEquals(OTPType.HOTP, result.account.type)
        assertEquals("alice@example.com", result.account.label)
        assertEquals(42L, result.account.counter)
        assertEquals(30, result.account.period)
    }

    @Test
    fun hotpUriParsesMaximumSupportedCounter() {
        val result = OTPURIParser.parse(
            "otpauth://hotp/Example:alice@example.com?secret=IFBEGRCFIZDUQSKKJNGE2TSPKBIVEU2U&issuer=Example&counter=9223372036854775807"
        )

        assertEquals(Long.MAX_VALUE, result.account.counter)
    }

    @Test
    fun totpAccountHasNullCounter() {
        val result = OTPURIParser.parse(
            "otpauth://totp/Example%3Aalice%40example.com?secret=IFBEGRCFIZDUQSKKJNGE2TSPKBIVEU2U&issuer=Example"
        )

        assertEquals(OTPType.TOTP, result.account.type)
        assertNull(result.account.counter)
    }
}
