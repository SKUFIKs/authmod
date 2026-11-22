package ru.undermine.authmod.auth;

import net.neoforged.neoforge.common.ModConfigSpec;

/**
 * Server config ({@code config/authmod-server.toml}) — used on dedicated servers
 * (and the integrated server in singleplayer).
 */
public final class AuthServerConfig {
    private static final ModConfigSpec.Builder BUILDER = new ModConfigSpec.Builder();

    public static final ModConfigSpec.BooleanValue ENABLED = BUILDER
            .comment("Enable the auth handshake and the /log, /reg limbo mode")
            .define("enabled", true);

    public static final ModConfigSpec.BooleanValue ALLOW_UNAUTHENTICATED_JOIN = BUILDER
            .comment("Let players without a valid token join in the restricted limbo mode instead of disconnecting")
            .define("allowUnauthenticatedJoin", true);

    public static final ModConfigSpec.BooleanValue ENFORCE_ON_INTEGRATED_SERVER = BUILDER
            .comment("Apply limbo restrictions on the integrated (singleplayer/LAN host) server as well")
            .define("enforceOnIntegratedServer", false);

    public static final ModConfigSpec.BooleanValue ALLOW_CLIENTS_WITHOUT_MOD = BUILDER
            .comment("Allow clients without the authmod installed (they cannot authenticate, so they stay in limbo)")
            .define("allowClientsWithoutMod", false);

    public static final ModConfigSpec.BooleanValue VALIDATE_WITH_API = BUILDER
            .comment("Check tokens against the UnderMine API (signature, expiry, ban, role, token version)")
            .define("validateWithApi", true);

    public static final ModConfigSpec.BooleanValue BIND_TOKEN_TO_PLAYER = BUILDER
            .comment("Reject a token whose account name does not match the joining player's name")
            .define("bindTokenToPlayer", true);

    public static final ModConfigSpec.ConfigValue<String> API_BASE_URL = BUILDER
            .comment("Base URL of the UnderMine API used to validate tokens")
            .define("apiBaseUrl", "https://staging.undermine.click");

    public static final ModConfigSpec.ConfigValue<String> VALIDATE_ENDPOINT = BUILDER
            .comment("Path of the validate-token endpoint, appended to the API base URL")
            .define("validateEndpoint", "/api/v1.0/validate-token");

    public static final ModConfigSpec.IntValue HTTP_TIMEOUT_SECONDS = BUILDER
            .comment("Timeout for the token validation HTTP request")
            .defineInRange("httpTimeoutSeconds", 10, 1, 120);

    public static final ModConfigSpec.IntValue VALIDATION_CACHE_SECONDS = BUILDER
            .comment("How long an accepted token is trusted without asking the API again (0 disables the cache)")
            .defineInRange("validationCacheSeconds", 300, 0, 86400);

    public static final ModConfigSpec.BooleanValue DISCONNECT_ON_VALIDATION_ERROR = BUILDER
            .comment("Disconnect when the token could not be validated during login (network error, non-200 response)")
            .define("disconnectOnValidationError", false);

    public static final ModConfigSpec.IntValue REMINDER_SECONDS = BUILDER
            .comment("How often unauthenticated players are reminded to use /log or /reg")
            .defineInRange("reminderSeconds", 8, 1, 300);

    public static final ModConfigSpec.IntValue AUTH_TIMEOUT_SECONDS = BUILDER
            .comment("How long an unauthenticated player may stay in limbo before being disconnected (0 disables the timer)")
            .defineInRange("authTimeoutSeconds", 120, 0, 3600);

    public static final ModConfigSpec.IntValue AUTH_ATTEMPT_COOLDOWN_SECONDS = BUILDER
            .comment("Minimum delay between authentication attempts from one player")
            .defineInRange("authAttemptCooldownSeconds", 3, 0, 60);

    public static final ModConfigSpec SPEC = BUILDER.build();

    private AuthServerConfig() {
    }
}
