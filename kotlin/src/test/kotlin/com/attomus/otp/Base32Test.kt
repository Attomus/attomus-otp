package com.attomus.otp

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class Base32Test {
    @Test
    fun decodesRfc4648Example() {
        assertArrayEquals(TestSupport.asciiData("Hello"), Base32.decode("JBSWY3DP"))
    }

    @Test
    fun decodesCaseInsensitiveInput() {
        assertArrayEquals(TestSupport.asciiData("Hello"), Base32.decode("jbswy3dp"))
    }

    @Test
    fun decodesWithWhitespace() {
        assertArrayEquals(TestSupport.asciiData("Hello"), Base32.decode("JBSW Y3DP"))
    }

    @Test
    fun decodesPaddingVariants() {
        assertArrayEquals(TestSupport.asciiData("f"), Base32.decode("MY======"))
        assertArrayEquals(TestSupport.asciiData("fo"), Base32.decode("MZXQ===="))
        assertArrayEquals(TestSupport.asciiData("foo"), Base32.decode("MZXW6==="))
        assertArrayEquals(TestSupport.asciiData("foob"), Base32.decode("MZXW6YQ="))
        assertArrayEquals(TestSupport.asciiData("fooba"), Base32.decode("MZXW6YTB"))
        assertArrayEquals(TestSupport.asciiData("foobar"), Base32.decode("MZXW6YTBOI======"))
    }

    @Test
    fun rejectsInvalidCharacter() {
        val error = assertThrows(Base32Error.InvalidCharacter::class.java) {
            Base32.decode("JBSWY3D!")
        }
        assertEquals('!', error.character)
    }

    @Test
    fun rejectsEmptyInput() {
        assertThrows(Base32Error.EmptyInput::class.java) {
            Base32.decode("")
        }
    }

    @Test
    fun rejectsAlphabetAfterPadding() {
        assertThrows(Base32Error.InvalidPadding::class.java) {
            Base32.decode("MY==A===")
        }
    }

    @Test
    fun rejectsNonZeroTrailingBits() {
        assertThrows(Base32Error.InvalidPadding::class.java) {
            Base32.decode("B")
        }
    }
}

