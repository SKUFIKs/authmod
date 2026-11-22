package ru.undermine.authmod.auth;

import net.neoforged.neoforge.common.ModConfigSpec;

/**
 * Client config ({@code config/authmod-client.toml}).
 */
public final class AuthConfig {
    private static final ModConfigSpec.Builder BUILDER = new ModConfigSpec.Builder();

    public static final ModConfigSpec.ConfigValue<String> API_BASE_URL = BUILDER
            .comment("Base URL of the UnderMine API (the launcher can override it through UNDERMINE_API_URL)")
            .define("apiBaseUrl", ApiEndpoints.DEFAULT_BASE_URL);

    public static final ModConfigSpec.ConfigValue<String> LOGIN_ENDPOINT = BUILDER
            .comment("Login endpoint, appended to the API base URL")
            .define("loginEndpoint", "/api/v1.0/login");

    public static final ModConfigSpec.ConfigValue<String> REGISTER_ENDPOINT = BUILDER
            .comment("Registration endpoint, appended to the API base URL")
            .define("registerEndpoint", "/api/v1.0/register");

    public static final ModConfigSpec.ConfigValue<String> VALIDATE_ENDPOINT = BUILDER
            .comment("Path of the validate-token endpoint, appended to the API base URL")
            .define("validateEndpoint", "/api/v1.0/validate-token");

    public static final ModConfigSpec.IntValue HTTP_TIMEOUT_SECONDS = BUILDER
            .comment("Timeout for API requests")
            .defineInRange("httpTimeoutSeconds", 15, 1, 120);

    public static final ModConfigSpec.BooleanValue REQUIRE_TOKEN = BUILDER
            .comment("Disconnect when no bearer token is available (servers without the auth mod)")
            .define("requireToken", true);

    public static final ModConfigSpec.BooleanValue KICK_ON_EXPIRED_TOKEN = BUILDER
            .comment("Disconnect when the token's exp claim is in the past")
            .define("kickOnExpiredToken", true);

    public static final ModConfigSpec.BooleanValue DISCONNECT_WHEN_INVALID = BUILDER
            .comment("Disconnect when the API reports the token as invalid")
            .define("disconnectWhenInvalid", true);

    public static final ModConfigSpec.BooleanValue DISCONNECT_ON_VALIDATION_ERROR = BUILDER
            .comment("Disconnect when the token could not be validated (network error, non-200 response, bad payload)")
            .define("disconnectOnValidationError", false);

    public static final ModConfigSpec.BooleanValue NOTIFY_ON_JOIN = BUILDER
            .comment("Show a chat message with the token status after joining a server")
            .define("notifyOnJoin", true);

    public static final ModConfigSpec.BooleanValue SEND_TOKEN_TO_SERVERS = BUILDER
            .comment("Send the bearer token to servers during the encrypted configuration handshake")
            .define("sendTokenToServers", true);

    public static final ModConfigSpec SPEC = BUILDER.build();

    private AuthConfig() {
    }
}
