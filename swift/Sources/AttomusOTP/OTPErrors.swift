import Foundation

public enum TOTPError: Error, Equatable, Sendable {
    case invalidSecret
    case invalidDigitCount
    case invalidAlgorithm
    case invalidPeriod
    case secretTooShort
    case secretTooLong
}

public enum HOTPError: Error, Equatable, Sendable {
    case invalidSecret
    case invalidDigitCount
    case invalidAlgorithm
    case secretTooShort
    case secretTooLong
}

public enum Base32Error: Error, Equatable, Sendable {
    case emptyInput
    case invalidCharacter(Character)
    case invalidPadding
}

public enum OTPURIError: Error, Equatable, Sendable {
    case uriTooLong
    case invalidScheme
    case invalidType
    case missingLabel
    case missingSecret
    case invalidSecret
    case secretTooShort
    case secretTooLong
    case invalidAlgorithm
    case invalidDigits
    case invalidPeriod
    case missingCounter
    case issuerMismatch
    case malformedPercentEncoding
}
