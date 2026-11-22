package ru.undermine.authmod.auth;

import java.util.concurrent.CompletableFuture;

import com.google.gson.JsonObject;

/**
 * Client-side /login and /register calls used by the in-game auth screen.
 *
 * <p>The API returns a token only from {@code /login}; {@code /register} just creates
 * the account, so registration transparently logs in afterwards.
 */
public final class AuthApiClient {
    private AuthApiClient() {
    }

    public record AuthResponse(
            boolean success,
            String message,
            String token,
            long userId,
            String login,
            String errorCode,
            int status) {

        public static AuthResponse failure(String message) {
            return new AuthResponse(false, message, "", 0L, "", "", 0);
        }
    }

    /**
     * Client entry point: API URL/endpoints come from the client config/environment.
     */
    public static CompletableFuture<AuthResponse> loginAsync(String login, String password) {
        return loginAsync(ApiEndpoints.baseUrl(), ApiEndpoints.loginEndpoint(), ApiEndpoints.timeoutSeconds(), login, password);
    }

    /**
     * Client entry point: registers the account and logs in on success.
     */
    public static CompletableFuture<AuthResponse> registerAsync(String login, String password, String deviceId) {
        return registerAsync(
                ApiEndpoints.baseUrl(),
                ApiEndpoints.loginEndpoint(),
                ApiEndpoints.registerEndpoint(),
                ApiEndpoints.timeoutSeconds(),
                login, password, deviceId);
    }

    public static CompletableFuture<AuthResponse> loginAsync(String baseUrl, String loginEndpoint, int timeoutSeconds,
                                                             String login, String password) {
        String url = ApiEndpoints.join(baseUrl, loginEndpoint);
        JsonObject payload = new JsonObject();
        payload.addProperty("login", login);
        payload.addProperty("password", password);

        return HttpJson.postAsync(url, null, payload.toString(), timeoutSeconds).thenApply(AuthApiClient::parseLogin);
    }

    public static CompletableFuture<AuthResponse> registerAsync(String baseUrl, String loginEndpoint, String registerEndpoint,
                                                                int timeoutSeconds, String login, String password, String deviceId) {
        String url = ApiEndpoints.join(baseUrl, registerEndpoint);
        JsonObject payload = new JsonObject();
        payload.addProperty("login", login);
        payload.addProperty("password", password);
        payload.addProperty("deviceID", deviceId);

        return HttpJson.postAsync(url, null, payload.toString(), timeoutSeconds).thenCompose(response -> {
            if (response.status() == 0) {
                return CompletableFuture.completedFuture(AuthResponse.failure(response.body()));
            }
            if (!response.ok()) {
                return CompletableFuture.completedFuture(parseFailure(response));
            }
            // Registration has no token: log in with the freshly created credentials.
            return loginAsync(baseUrl, loginEndpoint, timeoutSeconds, login, password);
        });
    }

    private static AuthResponse parseLogin(HttpJson.Response response) {
        if (response.status() == 0) {
            return AuthResponse.failure(response.body());
        }
        if (!response.ok()) {
            return parseFailure(response);
        }

        JsonObject json = HttpJson.parseObject(response.body());
        if (json == null) {
            return AuthResponse.failure("Unexpected response from the auth server.");
        }

        String token = optString(json, "token", "Token");
        if (token == null || token.isBlank()) {
            String message = optString(json, "message", "Message");
            return AuthResponse.failure(message == null || message.isBlank() ? "The auth server returned no token." : message);
        }

        return new AuthResponse(
                true,
                optStringOr(json, "message", "Message", ""),
                token,
                optLong(json, "userId", "UserId"),
                optStringOr(json, "login", "Login", ""),
                "",
                response.status());
    }

    private static AuthResponse parseFailure(HttpJson.Response response) {
        JsonObject json = HttpJson.parseObject(response.body());
        String message = json == null ? null : optString(json, "message", "Message");
        String error = json == null ? null : optString(json, "error", "Error");

        if (message == null || message.isBlank()) {
            message = switch (response.status()) {
                case 400 -> "Invalid request.";
                case 401 -> "Invalid username or password.";
                case 403 -> "This account is banned.";
                case 409 -> "This username is already taken.";
                case 429 -> "Too many attempts. Try again later.";
                default -> "Auth server error (HTTP " + response.status() + ").";
            };
        }

        return new AuthResponse(false, message, "", 0L, "", error == null ? "" : error, response.status());
    }

    private static String optString(JsonObject json, String... keys) {
        for (String key : keys) {
            if (json.has(key) && json.get(key).isJsonPrimitive()) {
                return json.get(key).getAsString();
            }
        }
        return null;
    }

    private static String optStringOr(JsonObject json, String key, String fallback) {
        String value = optString(json, key);
        return value == null ? fallback : value;
    }

    private static String optStringOr(JsonObject json, String a, String b, String fallback) {
        String value = optString(json, a, b);
        return value == null ? fallback : value;
    }

    private static long optLong(JsonObject json, String... keys) {
        for (String key : keys) {
            if (json.has(key) && json.get(key).isJsonPrimitive()) {
                try {
                    return json.get(key).getAsLong();
                } catch (RuntimeException ignored) {
                }
            }
        }
        return 0L;
    }

    /** Exposed for tests: parses a raw login response body. */
    public static AuthResponse parseLoginResponse(int status, String body) {
        return parseLogin(new HttpJson.Response(status, body));
    }
}
