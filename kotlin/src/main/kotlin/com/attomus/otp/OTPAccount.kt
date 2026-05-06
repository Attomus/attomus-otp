package com.attomus.otp

import java.util.Date
import java.util.UUID

data class OTPAccount(
    val id: UUID,
    val type: OTPType,
    val label: String,
    val issuer: String?,
    val algorithm: OTPAlgorithm,
    val digits: Int,
    val period: Int,
    val counter: Long? = null,
    val createdAt: Date = Date()
)

class OTPProvisioningResult(
    val account: OTPAccount,
    val secret: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is OTPProvisioningResult) return false
        if (account != other.account) return false
        if (!secret.contentEquals(other.secret)) return false
        return true
    }

    override fun hashCode(): Int {
        var result = account.hashCode()
        result = 31 * result + secret.contentHashCode()
        return result
    }

    override fun toString(): String {
        return "OTPProvisioningResult(account=$account, secret=<redacted>)"
    }
}
