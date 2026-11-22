package ru.undermine.authmod.net;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import javax.annotation.Nullable;
import javax.crypto.SecretKey;

import com.mojang.authlib.GameProfile;

import net.minecraft.network.Connection;
import net.minecraft.network.chat.Component;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.server.network.ServerCommonPacketListenerImpl;
import net.neoforged.neoforge.network.handling.IPayloadContext;

import ru.undermine.authmod.AuthMod;
import ru.undermine.authmod.auth.AuthServerConfig;
import ru.undermine.authmod.auth.JwtDecoder;
import ru.undermine.authmod.auth.TokenInfo;
import ru.undermine.authmod.auth.TokenValidator;
import ru.undermine.authmod.server.AuthEnforcement;
import ru.undermine.authmod.server.AuthState;

/**
 * Server side of the auth flow.
 *
 * <p>During the configuration phase the server validates the token supplied by the
 * launcher or in-game login screen and remembers the negotiated AES session key.
 * A player without a valid token is allowed in only when
 * {@code allowUnauthenticatedJoin} is enabled; they stay in the restricted limbo
 * until /log or /reg sends a new token over the encrypted play-phase channel.
 */
public final class ServerAuth {
    private static final long HANDSHAKE_TTL_SECONDS = 300;
    private static final int CACHE_PRUNE_THRESHOLD = 1024;

    /** Per-connection pending ECDH handshake. */
    private static final Map<Connection, Pending> HANDSHAKES = new ConcurrentHashMap<>();
    /** Per-connection AES key negotiated during the configuration handshake. */
    private static final Map<Connection, SecretKey> SESSION_KEYS = new ConcurrentHashMap<>();
    /** sha256(token) -&gt; epoch second until which the API already accepted it. */
    private static final Map<String, Long> ACCEPTED_TOKENS = new ConcurrentHashMap<>();

    private record Pending(AuthCrypto.PendingHandshake handshake, long createdAt) {
    }

    private ServerAuth() {
    }

    public static void registerHandshake(Connection connection, AuthCrypto.PendingHandshake handshake) {
        long now = Instant.now().getEpochSecond();
        HANDSHAKES.entrySet().removeIf(entry -> now - entry.getValue().createdAt() > HANDSHAKE_TTL_SECONDS);
        HANDSHAKES.put(connection, new Pending(handshake, now));
    }

    public static void clearConnection(Connection connection) {
        HANDSHAKES.remove(connection);
        SESSION_KEYS.remove(connection);
    }

    public static void clearAllSessions() {
        HANDSHAKES.clear();
        SESSION_KEYS.clear();
    }

    @Nullable
    private static AuthCrypto.PendingHandshake takeHandshake(Connection connection) {
        Pending pending = HANDSHAKES.remove(connection);
        return pending == null ? null : pending.handshake();
    }

    // --- configuration phase -------------------------------------------------

    public static void handleToken(AuthTokenPayload payload, IPayloadContext context) {
        AuthCrypto.PendingHandshake handshake = takeHandshake(context.connection());

        if (!AuthServerConfig.ENABLED.get()) {
            finish(context);
            return;
        }

        if (handshake == null) {
            AuthMod.LOGGER.warn("Rejecting a client: no pending auth handshake for this connection");
            disconnect(context, Component.translatable("message.authmod.server_handshake_failed"));
            return;
        }

        if (payload.version() != AuthCrypto.PROTOCOL_VERSION) {
            AuthMod.LOGGER.warn("Rejecting a client: unsupported auth payload version {}", payload.version());
            disconnect(context, Component.translatable("message.authmod.server_handshake_failed"));
            return;
        }

        AuthCrypto.DecryptedToken decrypted = AuthCrypto.decryptFromClient(
                handshake, payload.clientPublicKey(), payload.iv(), payload.ciphertext());
        if (decrypted == null) {
            // Without the session key the player could not authenticate later either.
            AuthMod.LOGGER.warn("Rejecting a client: the encrypted token could not be decrypted");
            disconnect(context, Component.translatable("message.authmod.server_handshake_failed"));
            return;
        }

        // Keep the key: /log and /reg use it to send the token after the player has joined.
        SESSION_KEYS.put(context.connection(), decrypted.sessionKey());

        final String token = decrypted.token().trim();
        GameProfile profile = profile(context);
        UUID playerId = profile == null ? null : profile.getId();
        if (playerId != null) {
            AuthState.setAccountHint(playerId, payload.knownAccount());
        }

        if (token.isEmpty()) {
            rejectLogin(context, playerId, Component.translatable("message.authmod.server_no_token"));
            return;
        }

        TokenInfo info;
        try {
            info = JwtDecoder.decode(token, "encrypted handshake");
        } catch (IllegalArgumentException e) {
            AuthMod.LOGGER.warn("Token is malformed: {}", e.getMessage());
            rejectLogin(context, playerId, Component.translatable("message.authmod.server_token_malformed"));
            return;
        }

        long now = Instant.now().getEpochSecond();
        if (info.isExpired(now)) {
            AuthMod.LOGGER.warn("Token of {} expired at {}", info.name(), info.formattedExpiry());
            rejectLogin(context, playerId, Component.translatable("message.authmod.server_token_expired", info.formattedExpiry()));
            return;
        }

        if (AuthServerConfig.BIND_TOKEN_TO_PLAYER.get()
                && profile != null && info.name() != null
                && !profile.getName().equalsIgnoreCase(info.name())) {
            AuthMod.LOGGER.warn("Token of {} used by player {}: account mismatch", info.name(), profile.getName());
            rejectLogin(context, playerId,
                    Component.translatable("message.authmod.server_token_mismatch", info.name(), profile.getName()));
            return;
        }

        if (isTokenCached(token, now)) {
            acceptLogin(context, playerId, token, info);
            return;
        }

        if (!AuthServerConfig.VALIDATE_WITH_API.get()) {
            acceptLogin(context, playerId, token, info);
            return;
        }

        String baseUrl = AuthServerConfig.API_BASE_URL.get().trim();
        String endpoint = AuthServerConfig.VALIDATE_ENDPOINT.get().trim();
        int timeoutSeconds = AuthServerConfig.HTTP_TIMEOUT_SECONDS.get();

        TokenValidator.validateAsync(baseUrl, endpoint, timeoutSeconds, token).whenComplete((result, error) -> {
            if (error != null) {
                AuthMod.LOGGER.error("Token validation failed unexpectedly", error);
                context.enqueueWork(() -> onLoginValidation(context, playerId, token, info,
                        new TokenValidator.Result(TokenValidator.Outcome.ERROR, String.valueOf(error), "")));
                return;
            }
            context.enqueueWork(() -> onLoginValidation(context, playerId, token, info, result));
        });
    }

    private static void onLoginValidation(IPayloadContext context, @Nullable UUID playerId, String token,
                                          TokenInfo info, TokenValidator.Result result) {
        switch (result.outcome()) {
            case VALID -> acceptLogin(context, playerId, token, info);
            case INVALID -> {
                AuthMod.LOGGER.warn("Rejected token for {}: {} ({})", info.name(), detail(result), result.errorCode());
                rejectLogin(context, playerId, Component.translatable("message.authmod.server_token_invalid", detail(result)));
            }
            case ERROR -> {
                AuthMod.LOGGER.warn("Could not validate the token for {}: {}", info.name(), result.message());
                if (AuthServerConfig.DISCONNECT_ON_VALIDATION_ERROR.get()) {
                    disconnect(context, Component.translatable("message.authmod.server_validation_unavailable", result.message()));
                } else {
                    rejectLogin(context, playerId,
                            Component.translatable("message.authmod.server_validation_unavailable", result.message()));
                }
            }
        }
    }

    private static void acceptLogin(IPayloadContext context, @Nullable UUID playerId, String token, TokenInfo info) {
        if (playerId != null) {
            AuthState.markAuthenticated(playerId);
        }
        cacheToken(token, info);
        AuthMod.LOGGER.info("Accepted token for {} ({})", info.name(), info.role());
        finish(context);
    }

    private static void rejectLogin(IPayloadContext context, @Nullable UUID playerId, Component reason) {
        if (playerId != null) {
            AuthState.markUnauthenticated(playerId, reason);
        }

        if (AuthServerConfig.ALLOW_UNAUTHENTICATED_JOIN.get()) {
            AuthMod.LOGGER.info("Unauthenticated player{} joins in limbo", playerId == null ? "" : " " + playerId);
            finish(context);
        } else {
            disconnect(context, reason);
        }
    }

    // --- play phase: /log and /reg -------------------------------------------

    public static void handleSessionToken(AuthSessionPayload payload, IPayloadContext context) {
        if (!(context.player() instanceof ServerPlayer player) || !AuthServerConfig.ENABLED.get()) {
            return;
        }

        UUID playerId = player.getUUID();
        if (AuthState.isAuthenticated(playerId)) {
            player.sendSystemMessage(Component.translatable("authmod.auth.already_authenticated"));
            return;
        }

        if (!AuthState.attemptDue(playerId, AuthServerConfig.AUTH_ATTEMPT_COOLDOWN_SECONDS.get())) {
            player.sendSystemMessage(Component.translatable("authmod.auth.too_fast"));
            return;
        }

        if (payload.version() != AuthCrypto.PROTOCOL_VERSION) {
            player.sendSystemMessage(Component.translatable("authmod.auth.login_failed", "protocol mismatch"));
            return;
        }

        SecretKey key = SESSION_KEYS.get(context.connection());
        if (key == null) {
            player.sendSystemMessage(Component.translatable("authmod.auth.session_lost"));
            return;
        }

        String decrypted = AuthCrypto.decryptWithKey(key, payload.iv(), payload.ciphertext());
        if (decrypted == null) {
            player.sendSystemMessage(Component.translatable("authmod.auth.login_failed", "decryption failed"));
            return;
        }
        final String token = decrypted.trim();
        if (token.isEmpty()) {
            player.sendSystemMessage(Component.translatable("authmod.auth.login_failed", "empty token"));
            return;
        }

        TokenInfo info;
        try {
            info = JwtDecoder.decode(token, "session channel");
        } catch (IllegalArgumentException e) {
            player.sendSystemMessage(Component.translatable("authmod.auth.login_failed", "malformed token"));
            return;
        }

        if (info.isExpired(Instant.now().getEpochSecond())) {
            player.sendSystemMessage(Component.translatable("authmod.auth.login_failed", "expired token"));
            return;
        }

        if (AuthServerConfig.BIND_TOKEN_TO_PLAYER.get()
                && info.name() != null
                && !player.getGameProfile().getName().equalsIgnoreCase(info.name())) {
            player.sendSystemMessage(Component.translatable("message.authmod.server_token_mismatch",
                    info.name(), player.getGameProfile().getName()));
            return;
        }

        if (isTokenCached(token, Instant.now().getEpochSecond())) {
            acceptSession(player, token, info);
            return;
        }

        if (!AuthServerConfig.VALIDATE_WITH_API.get()) {
            acceptSession(player, token, info);
            return;
        }

        String baseUrl = AuthServerConfig.API_BASE_URL.get().trim();
        String endpoint = AuthServerConfig.VALIDATE_ENDPOINT.get().trim();
        int timeoutSeconds = AuthServerConfig.HTTP_TIMEOUT_SECONDS.get();

        TokenValidator.validateAsync(baseUrl, endpoint, timeoutSeconds, token).whenComplete((result, error) -> {
            if (error != null) {
                context.enqueueWork(() -> player.sendSystemMessage(
                        Component.translatable("authmod.auth.login_failed", String.valueOf(error))));
                return;
            }
            context.enqueueWork(() -> onSessionValidation(player, token, info, result));
        });
    }

    private static void onSessionValidation(ServerPlayer player, String token, TokenInfo info, TokenValidator.Result result) {
        switch (result.outcome()) {
            case VALID -> acceptSession(player, token, info);
            case INVALID -> {
                AuthMod.LOGGER.warn("Rejected /log token for {}: {} ({})",
                        info.name(), detail(result), result.errorCode());
                player.sendSystemMessage(Component.translatable("authmod.auth.login_failed", detail(result)));
            }
            case ERROR -> {
                AuthMod.LOGGER.warn("Could not validate the /log token for {}: {}", info.name(), result.message());
                player.sendSystemMessage(Component.translatable("authmod.auth.login_failed", result.message()));
            }
        }
    }

    private static void acceptSession(ServerPlayer player, String token, TokenInfo info) {
        AuthState.markAuthenticated(player.getUUID());
        cacheToken(token, info);
        AuthEnforcement.clearBlindness(player);
        player.sendSystemMessage(Component.translatable("authmod.auth.login_success",
                info.name() == null ? player.getGameProfile().getName() : info.name()));
        AuthMod.LOGGER.info("Player {} authenticated via /log", player.getGameProfile().getName());
    }

    /**
     * Client learned from the API that the account exists (or not) and updates the
     * /log vs /reg hint shown in the limbo reminders.
     */
    public static void handleAccountHint(AuthAccountHintPayload payload, IPayloadContext context) {
        if (context.player() instanceof ServerPlayer player && AuthServerConfig.ENABLED.get()) {
            AuthState.setAccountHint(player.getUUID(), payload.knownAccount());
        }
    }

    // --- helpers -------------------------------------------------------------

    @Nullable
    private static GameProfile profile(IPayloadContext context) {
        try {
            if (context.listener() instanceof ServerCommonPacketListenerImpl listener) {
                return listener.getOwner();
            }
        } catch (RuntimeException ignored) {
            // Unexpected listener type.
        }
        return null;
    }

    private static String detail(TokenValidator.Result result) {
        String message = result.message() == null || result.message().isBlank() ? "invalid token" : result.message();
        return result.errorCode() == null || result.errorCode().isBlank()
                ? message
                : result.errorCode() + ": " + message;
    }

    private static void finish(IPayloadContext context) {
        HANDSHAKES.remove(context.connection());
        try {
            context.finishCurrentTask(AuthConfigurationTask.TYPE);
        } catch (RuntimeException e) {
            AuthMod.LOGGER.debug("Could not finish the auth configuration task: {}", e.toString());
        }
    }

    private static void disconnect(IPayloadContext context, Component reason) {
        clearConnection(context.connection());
        try {
            context.disconnect(reason);
        } catch (RuntimeException e) {
            AuthMod.LOGGER.debug("Could not disconnect the client: {}", e.toString());
        }
    }

    // --- validation cache ---------------------------------------------------

    private static boolean isTokenCached(String token, long nowEpochSeconds) {
        int ttl = AuthServerConfig.VALIDATION_CACHE_SECONDS.get();
        if (ttl <= 0) {
            return false;
        }
        String key = hash(token);
        Long validUntil = ACCEPTED_TOKENS.get(key);
        if (validUntil == null) {
            return false;
        }
        if (validUntil <= nowEpochSeconds) {
            ACCEPTED_TOKENS.remove(key);
            return false;
        }
        return true;
    }

    private static void cacheToken(String token, TokenInfo info) {
        int ttl = AuthServerConfig.VALIDATION_CACHE_SECONDS.get();
        if (ttl <= 0) {
            return;
        }
        long now = Instant.now().getEpochSecond();
        long validUntil = now + ttl;
        if (info.hasExpiry()) {
            validUntil = Math.min(validUntil, info.expiresAtEpochSeconds());
        }
        if (validUntil <= now) {
            return;
        }
        if (ACCEPTED_TOKENS.size() > CACHE_PRUNE_THRESHOLD) {
            ACCEPTED_TOKENS.entrySet().removeIf(entry -> entry.getValue() <= now);
        }
        ACCEPTED_TOKENS.put(hash(token), validUntil);
    }

    private static String hash(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            return token; // SHA-256 is mandatory for every JVM; this is unreachable.
        }
    }
}
