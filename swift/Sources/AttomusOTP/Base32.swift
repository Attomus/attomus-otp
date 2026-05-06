import Foundation

public enum Base32 {
    private static let alphabet: [Character: UInt8] = [
        "A": 0, "B": 1, "C": 2, "D": 3, "E": 4, "F": 5, "G": 6, "H": 7,
        "I": 8, "J": 9, "K": 10, "L": 11, "M": 12, "N": 13, "O": 14, "P": 15,
        "Q": 16, "R": 17, "S": 18, "T": 19, "U": 20, "V": 21, "W": 22, "X": 23,
        "Y": 24, "Z": 25, "2": 26, "3": 27, "4": 28, "5": 29, "6": 30, "7": 31
    ]
    private static let alphabetCharacters: [Character] = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

    public static func encode(_ data: Data) -> String {
        guard !data.isEmpty else {
            return ""
        }

        var output = String()
        output.reserveCapacity((data.count * 8 + 4) / 5)

        var buffer = UInt32(0)
        var bitCount = 0

        for byte in data {
            buffer = (buffer << 8) | UInt32(byte)
            bitCount += 8

            while bitCount >= 5 {
                bitCount -= 5
                let index = Int((buffer >> UInt32(bitCount)) & 0x1F)
                output.append(alphabetCharacters[index])
                buffer &= (1 << UInt32(bitCount)) - 1
            }
        }

        if bitCount > 0 {
            let index = Int((buffer << UInt32(5 - bitCount)) & 0x1F)
            output.append(alphabetCharacters[index])
        }

        return output
    }

    public static func decode(_ encoded: String) throws -> Data {
        let sanitized = encoded.filter { !$0.isWhitespace }
        guard !sanitized.isEmpty else {
            throw Base32Error.emptyInput
        }

        var buffer = UInt32(0)
        var bitCount = 0
        var bytes: [UInt8] = []
        var sawPadding = false

        for scalar in sanitized.uppercased() {
            if scalar == "=" {
                sawPadding = true
                continue
            }

            if sawPadding {
                throw Base32Error.invalidPadding
            }

            guard let value = alphabet[scalar] else {
                throw Base32Error.invalidCharacter(scalar)
            }

            buffer = (buffer << 5) | UInt32(value)
            bitCount += 5

            while bitCount >= 8 {
                bitCount -= 8
                let nextByte = UInt8((buffer >> UInt32(bitCount)) & 0xFF)
                bytes.append(nextByte)
                buffer &= (1 << UInt32(bitCount)) - 1
            }
        }

        if bitCount > 0 {
            let trailingMask = (UInt32(1) << UInt32(bitCount)) - 1
            if (buffer & trailingMask) != 0 {
                throw Base32Error.invalidPadding
            }
        }

        return Data(bytes)
    }
}
