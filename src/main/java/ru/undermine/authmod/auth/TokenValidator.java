package ru.undermine.authmod.auth;

import java.util.concurrent.CompletableFuture;

import com.google.gson.JsonObject;

/**
 * Validates a bearer token against the UnderMine API:
 * {@code POST <apiBaseUrl><validateEndpoint>} with the {@code Authorization: Bearer ...} header.
 *
 * <p>The API answers {@code 200 {"valid":true,...}} for a good token and {@code 401}/{@code 403}
 * with {@code {"valid":false,"error":"TOKEN_REVOKED","message":"..."}} otherwise.
 */
public final class TokenValidator {
    private TokenValidator() {
    }

    public enum Outcome {
        VALID, INVALID, ERROR
    }

    /**
     * @param message   human-readable message from the API, or an error description
     * @param errorCode machine-readable code from the API ({@code TOKEN_REVOKED}, {@code ACCOUNT_BANNED}, ...)
     */
    public record Result(Outcome outcome, String message, String errorCode) {
        public boolean valid() {
            return outcome == Outcome.VALID;
        }
    }

    /**
     * Client-side entry point using the client config/environment.
     */
    public static CompletableFuture<Result> validateAsync(String token) {
        return validateAsync(ApiEndpoints.baseUrl(), ApiEndpoints.validateEndpoint(), ApiEndpoints.timeoutSeconds(), token);
    }

    /**
     * Fire an async validation request. Config values must be read on the calling
     * (game/server) thread; the request itself runs on the background executor.
     */
    public static CompletableFuture<Result> validateAsync(String baseUrl, String endpoint, int timeoutSeconds, String token) {
        if (token == null || token.isBlank()) {
            return CompletableFuture.completedFuture(new Result(Outcome.ERROR, "Token is empty", ""));
        }

        String url;
        try {
            url = ApiEndpoints.join(baseUrl, endpoint);
        } catch (RuntimeException e) {
            return CompletableFuture.completedFuture(new Result(Outcome.ERROR, String.valueOf(e.getMessage()), ""));
        }

        return HttpJson.postAsync(url, token, null, timeoutSeconds).thenApply(TokenValidator::parseResponse);
    }

    private static Result parseResponse(HttpJson.Response response) {
        if (response.status() == 0) {
            return new Result(Outcome.ERROR, response.body(), "");
        }
        return parse(response.status(), response.body());
    }

    /**
     * {@code 401}/{@code 403} mean the token is invalid; other non-2xx statuses are errors.
     */
    static Result parse(int status, String body) {
        boolean rejected = status == 401 || status == 403;
        JsonObject json = HttpJson.parseObject(body);

        if (json != null) {
            Boolean valid = optBoolean(json, "valid", "Valid");
            String message = optString(json, "message", "Message");
            String error = optString(json, "error", "Error");

            if (valid != null) {
                return new Result(valid ? Outcome.VALID : Outcome.INVALID,
                        message == null || message.isBlank() ? "HTTP " + status : message,
                        error == null ? "" : error);
            }
            if (rejected) {
                return new Result(Outcome.INVALID,
                        message == null || message.isBlank() ? "HTTP " + status : message,
                        error == null ? "" : error);
            }
            return new Result(Outcome.ERROR, "unexpected response" + snippet(body), "");
        }

        if (rejected) {
            return new Result(Outcome.INVALID, "HTTP " + status, "");
        }
        return new Result(Outcome.ERROR, "bad response " + status + snippet(body), "");
    }

    private static String snippet(String body) {
        if (body == null) {
            return "";
        }
        String trimmed = body.strip();
        if (trimmed.length() > 160) {
            trimmed = trimmed.substring(0, 160) + "...";
        }
        return " (" + trimmed + ")";
    }

    private static Boolean optBoolean(JsonObject json, String... keys) {
        for (String key : keys) {
            if (json.has(key) && json.get(key).isJsonPrimitive()) {
                try {
                    return json.get(key).getAsBoolean();
                } catch (RuntimeException ignored) {
                }
            }
        }
        return null;
    }

    private static String optString(JsonObject json, String... keys) {
        for (String key : keys) {
            if (json.has(key) && json.get(key).isJsonPrimitive()) {
                return json.get(key).getAsString();
            }
        }
        return null;
    }
}
