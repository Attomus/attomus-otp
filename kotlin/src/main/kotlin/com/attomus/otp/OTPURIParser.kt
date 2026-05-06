package com.attomus.otp

import java.io.ByteArrayOutputStream
import java.nio.charset.CharacterCodingException
import java.math.BigInteger
import java.net.URI
import java.net.URISyntaxException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.Date
import java.util.UUID

@Suppress("TooManyFunctions")
object OTPURIParser {
    @Suppress("ThrowsCount")
    fun parse(uri: String): OTPProvisioningResult {
        val components = parseComponents(uri)
        val type = parseType(components)
        val label = parseLabel(components.rawPath)
        val parameters = parseParameters(components.rawQuery)

        val encodedSecret = parameters["secret"]
        if (encodedSecret.isNullOrEmpty()) {
            throw OTPURIError.MissingSecret
        }

        val secret = try {
            Base32.decode(encodedSecret)
        } catch (_: Base32Error) {
            throw OTPURIError.InvalidSecret
        }

        try {
            OTPValidation.validateURISecret(secret)

            return OTPProvisioningResult(
                account = makeAccount(type, label, parameters),
                secret = secret
            )
        } catch (error: OTPURIError) {
            secret.zero()
            throw error
        }
    }

    @Suppress("ThrowsCount")
    private fun parseComponents(uri: String): URI {
        if (uri.length > 2048) {
            throw OTPURIError.UriTooLong
        }

        validatePercentEncoding(uri)

        val components = try {
            URI(uri)
        } catch (_: URISyntaxException) {
            throw OTPURIError.InvalidScheme
        } catch (_: IllegalArgumentException) {
            throw OTPURIError.InvalidScheme
        }

        if (!components.scheme.equals("otpauth", ignoreCase = true)) {
            throw OTPURIError.InvalidScheme
        }

        return components
    }

    private fun parseType(components: URI): OTPType {
        val rawType = components.host ?: throw OTPURIError.InvalidType
        return when {
            rawType.equals("totp", ignoreCase = true) -> OTPType.TOTP
            rawType.equals("hotp", ignoreCase = true) -> OTPType.HOTP
            else -> throw OTPURIError.InvalidType
        }
    }

    @Suppress("ThrowsCount")
    private fun parseLabel(rawPath: String?): LabelParts {
        val path = rawPath?.removePrefix("/") ?: ""
        if (path.isEmpty()) {
            throw OTPURIError.MissingLabel
        }

        val decoded = percentDecode(path)
        val parts = decoded.split(":", limit = 2)
        return if (parts.size == 2) {
            val issuer = parts[0].trim().ifEmpty { null }
            val accountName = parts[1].trim()
            if (accountName.isEmpty()) {
                throw OTPURIError.MissingLabel
            }
            LabelParts(issuer = issuer, accountName = accountName)
        } else {
            val accountName = decoded.trim()
            if (accountName.isEmpty()) {
                throw OTPURIError.MissingLabel
            }
            LabelParts(issuer = null, accountName = accountName)
        }
    }

    private fun parseParameters(rawQuery: String?): Map<String, String> {
        if (rawQuery.isNullOrEmpty()) {
            return emptyMap()
        }

        val parameters = linkedMapOf<String, String>()
        rawQuery.split("&")
            .asSequence()
            .filter { it.isNotEmpty() }
            .forEach { pair ->
                val equalsIndex = pair.indexOf('=')
                val rawName = if (equalsIndex >= 0) pair.substring(0, equalsIndex) else pair
                val rawValue = if (equalsIndex >= 0) pair.substring(equalsIndex + 1) else ""
                val name = percentDecode(rawName).lowercase()
                val value = percentDecode(rawValue)
                parameters.putIfAbsent(name, value)
            }

        return parameters
    }

    private fun makeAccount(
        type: OTPType,
        label: LabelParts,
        parameters: Map<String, String>
    ): OTPAccount {
        val algorithm = parseAlgorithm(parameters["algorithm"])
        val digits = parseDigits(parameters["digits"])
        val period = parsePeriod(parameters["period"], type)
        val issuer = resolveIssuer(label.issuer, parameters["issuer"])
        val counter = if (type == OTPType.HOTP) parseCounter(parameters["counter"]) else null

        return OTPAccount(
            id = UUID.randomUUID(),
            type = type,
            label = label.accountName,
            issuer = issuer,
            algorithm = algorithm,
            digits = digits,
            period = period,
            counter = counter,
            createdAt = Date()
        )
    }

    private fun parseAlgorithm(rawValue: String?): OTPAlgorithm {
        val value = rawValue?.trim().orEmpty()
        if (value.isEmpty()) {
            return OTPAlgorithm.SHA1
        }

        return when (value.lowercase()) {
            "sha1" -> OTPAlgorithm.SHA1
            "sha256" -> OTPAlgorithm.SHA256
            "sha512" -> OTPAlgorithm.SHA512
            else -> throw OTPURIError.InvalidAlgorithm
        }
    }

    private fun parseDigits(rawValue: String?): Int {
        val value = rawValue?.trim().orEmpty()
        if (value.isEmpty()) {
            return 6
        }

        val digits = value.toIntOrNull() ?: throw OTPURIError.InvalidDigits
        OTPValidation.validateURIDigits(digits)
        return digits
    }

    @Suppress("ReturnCount")
    private fun parsePeriod(rawValue: String?, type: OTPType): Int {
        return when {
            type == OTPType.HOTP -> 30
            rawValue.isNullOrBlank() -> 30
            else -> {
                val period = rawValue.trim().toIntOrNull() ?: throw OTPURIError.InvalidPeriod
                OTPValidation.validateURIPeriod(period)
                period
            }
        }
    }

    @Suppress("ThrowsCount")
    private fun parseCounter(rawValue: String?): Long {
        val value = rawValue?.trim().orEmpty()
        if (value.isEmpty()) {
            throw OTPURIError.MissingCounter
        }

        val counter = try {
            BigInteger(value)
        } catch (_: Exception) {
            throw OTPURIError.MissingCounter
        }

        if (counter.signum() < 0 || counter.bitLength() > 64) {
            throw OTPURIError.MissingCounter
        }

        return counter.toLong()
    }

    private fun resolveIssuer(labelIssuer: String?, parameterIssuer: String?): String? {
        val normalizedParameter = parameterIssuer?.trim().orEmpty().ifEmpty { null }
        if (labelIssuer != null && normalizedParameter != null && labelIssuer != normalizedParameter) {
            throw OTPURIError.IssuerMismatch
        }
        return normalizedParameter ?: labelIssuer
    }

    private fun validatePercentEncoding(text: String) {
        var index = 0
        while (index < text.length) {
            if (text[index] == '%') {
                if (index + 2 >= text.length) {
                    throw OTPURIError.MalformedPercentEncoding
                }
                val first = text[index + 1]
                val second = text[index + 2]
                if (!first.isHexDigit() || !second.isHexDigit()) {
                    throw OTPURIError.MalformedPercentEncoding
                }
                index += 3
                continue
            }
            index += 1
        }
    }

    private fun percentDecode(text: String): String {
        val output = StringBuilder()
        val bytes = ByteArrayOutputStream()

        fun flushBytes() {
            if (bytes.size() == 0) {
                return
            }

            val decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)

            val decoded = try {
                decoder.decode(java.nio.ByteBuffer.wrap(bytes.toByteArray())).toString()
            } catch (_: CharacterCodingException) {
                throw OTPURIError.MalformedPercentEncoding
            }

            output.append(decoded)
            bytes.reset()
        }

        var index = 0
        while (index < text.length) {
            val character = text[index]
            if (character == '%') {
                if (index + 2 >= text.length) {
                    throw OTPURIError.MalformedPercentEncoding
                }

                val first = text[index + 1]
                val second = text[index + 2]
                if (!first.isHexDigit() || !second.isHexDigit()) {
                    throw OTPURIError.MalformedPercentEncoding
                }

                val byteValue = ((hexValue(first) shl 4) or hexValue(second)).toByte()
                bytes.write(byteValue.toInt())
                index += 3
                continue
            }

            flushBytes()
            output.append(character)
            index += 1
        }

        flushBytes()
        return output.toString()
    }

    private fun Int.isHexDigit(): Boolean = this in 0..15

    private fun Char.isHexDigit(): Boolean = hexValue(this) >= 0

    private fun hexValue(character: Char): Int {
        return when (character) {
            in '0'..'9' -> character - '0'
            in 'a'..'f' -> 10 + (character - 'a')
            in 'A'..'F' -> 10 + (character - 'A')
            else -> -1
        }
    }

    private fun ByteArray.zero() {
        fill(0)
    }

    private data class LabelParts(
        val issuer: String?,
        val accountName: String
    )
}
