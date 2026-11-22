package ru.undermine.authmod.auth;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

import javax.annotation.Nullable;

/**
 * Parsed (but not cryptographically verified) payload of the bearer token.
 * The signature is never verified here — the API decides validity via
 * {@code POST /api/v1.0/validate-token}.
 */
public record TokenInfo(
        String token,
        String source,
        @Nullable String name,
        @Nullable String userId,
        @Nullable String role,
        long expiresAtEpochSeconds) {

    public boolean hasExpiry() {
        return expiresAtEpochSeconds > 0;
    }

    public boolean isExpired(long nowEpochSeconds) {
        return hasExpiry() && nowEpochSeconds >= expiresAtEpochSeconds;
    }

    /**
     * Formatted expiry time in the local time zone, or "-" when the token has no exp claim.
     */
    public String formattedExpiry() {
        if (!hasExpiry()) {
            return "-";
        }
        return DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm")
                .format(Instant.ofEpochSecond(expiresAtEpochSeconds).atZone(ZoneId.systemDefault()));
    }
}
