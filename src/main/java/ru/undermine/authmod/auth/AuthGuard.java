package ru.undermine.authmod.auth;

import javax.annotation.Nullable;

import net.minecraft.network.chat.Component;
import ru.undermine.authmod.AuthMod;

/**
 * Combined "is this session allowed to join" check:
 * local checks (token present, decodable, not expired) performed on the game thread.
 */
public final class AuthGuard {
    private AuthGuard() {
    }

    /**
     * Result of the local check. When {@link #failure} is {@code null} the session may
     * proceed, and {@link #info} contains the parsed token.
     */
    public record Check(@Nullable Component failure, @Nullable LauncherTokenProvider.Found found, @Nullable TokenInfo info) {
        public boolean ok() {
            return failure == null;
        }
    }

    public static Check check() {
        LauncherTokenProvider.Found found = LauncherTokenProvider.find().orElse(null);
        if (found == null) {
            if (AuthConfig.REQUIRE_TOKEN.get()) {
                return new Check(Component.translatable("message.authmod.no_token"), null, null);
            }
            AuthMod.LOGGER.debug("No bearer token provided by the launcher, continuing (requireToken=false)");
            return new Check(null, null, null);
        }

        TokenInfo info;
        try {
            info = JwtDecoder.decode(found.token(), found.source());
        } catch (IllegalArgumentException e) {
            AuthMod.LOGGER.warn("Bearer token from {} is malformed: {}", found.source(), e.getMessage());
            if (AuthConfig.REQUIRE_TOKEN.get()) {
                return new Check(Component.translatable("message.authmod.token_malformed"), found, null);
            }
            return new Check(null, found, null);
        }

        if (info.isExpired(java.time.Instant.now().getEpochSecond())) {
            if (AuthConfig.KICK_ON_EXPIRED_TOKEN.get()) {
                AuthMod.LOGGER.warn("Bearer token from {} expired at {}", found.source(), info.formattedExpiry());
                return new Check(Component.translatable("message.authmod.token_expired", info.formattedExpiry()), found, info);
            }
            AuthMod.LOGGER.debug("Bearer token is expired but kickOnExpiredToken is disabled");
        }

        return new Check(null, found, info);
    }
}
