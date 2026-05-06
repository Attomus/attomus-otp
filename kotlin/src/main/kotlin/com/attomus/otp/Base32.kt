package com.attomus.otp

object Base32 {
    private val alphabet: Map<Char, Int> = mapOf(
        'A' to 0, 'B' to 1, 'C' to 2, 'D' to 3, 'E' to 4, 'F' to 5, 'G' to 6, 'H' to 7,
        'I' to 8, 'J' to 9, 'K' to 10, 'L' to 11, 'M' to 12, 'N' to 13, 'O' to 14, 'P' to 15,
        'Q' to 16, 'R' to 17, 'S' to 18, 'T' to 19, 'U' to 20, 'V' to 21, 'W' to 22, 'X' to 23,
        'Y' to 24, 'Z' to 25, '2' to 26, '3' to 27, '4' to 28, '5' to 29, '6' to 30, '7' to 31
    )

    @Suppress("ThrowsCount")
    fun decode(encoded: String): ByteArray {
        val sanitized = encoded.filterNot(Char::isWhitespace)
        if (sanitized.isEmpty()) {
            throw Base32Error.EmptyInput
        }

        val buffer = ByteArray((sanitized.length * 5) / 8 + 1)
        var bufferValue = 0
        var bitCount = 0
        var outputIndex = 0
        var sawPadding = false
        var sawAlphabetCharacter = false

        try {
            for (character in sanitized.uppercase()) {
                if (character == '=') {
                    sawPadding = true
                    continue
                }

                if (sawPadding) {
                    throw Base32Error.InvalidPadding
                }

                val value = alphabet[character] ?: throw Base32Error.InvalidCharacter(character)
                sawAlphabetCharacter = true

                bufferValue = (bufferValue shl 5) or value
                bitCount += 5

                while (bitCount >= 8) {
                    bitCount -= 8
                    buffer[outputIndex] = ((bufferValue shr bitCount) and 0xFF).toByte()
                    outputIndex += 1
                    bufferValue = bufferValue and ((1 shl bitCount) - 1)
                }
            }

            if (!sawAlphabetCharacter) {
                throw Base32Error.EmptyInput
            }

            if (bitCount > 0) {
                val trailingMask = (1 shl bitCount) - 1
                if ((bufferValue and trailingMask) != 0) {
                    throw Base32Error.InvalidPadding
                }
            }

            return buffer.copyOf(outputIndex)
        } finally {
            buffer.zero()
        }
    }

    private fun ByteArray.zero() {
        fill(0)
    }
}
