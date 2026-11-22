package ru.undermine.authmod.auth;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.annotation.Nullable;

/**
 * Minimal JWT payload decoder (base64url of the second segment, parsed with Gson).
 * No signature verification — that is the API's job.
 */
public final class JwtDecoder {
    private static final String NAME_CLAIM = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";
    private static final String ROLE_CLAIM = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role";

    private JwtDecoder() {
    }

    /**
     * @throws IllegalArgumentException when the token is not decodable as a JWT
     */
    public static TokenInfo decode(String token, String source) {
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("Token is empty");
        }
        String[] parts = token.trim().split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("Token is not a JWT (expected 3 dot-separated segments)");
        }
        String payload;
        try {
            payload = new String(decodeBase64Url(parts[1]), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Token payload is not valid base64url", e);
        }
        JsonObject json;
        try {
            json = JsonParser.parseString(payload).getAsJsonObject();
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("Token payload is not a JSON object", e);
        }

        // The API serializes ClaimTypes.Name/Role as their full XML schema URIs, while older
        // tokens (and tests) may carry the short JWT names. Accept both.
        String name = firstString(json, NAME_CLAIM, "unique_name", "name", "preferred_username", "sub");
        String userId = firstString(json, "UserId", "user_id", "sub");
        String role = firstString(json, ROLE_CLAIM, "role", "roles");
        long exp = firstLong(json, "exp");

        return new TokenInfo(token, source, name, userId, role, exp);
    }

    private static byte[] decodeBase64Url(String input) {
        int padding = (4 - input.length() % 4) % 4;
        return Base64.getUrlDecoder().decode(input + "=".repeat(padding));
    }

    @Nullable
    private static String firstString(JsonObject json, String... names) {
        for (String key : names) {
            if (json.has(key) && json.get(key).isJsonPrimitive()) {
                String value = json.get(key).getAsString();
                if (value != null && !value.isBlank()) {
                    return value;
                }
            }
        }
        return null;
    }

    private static long firstLong(JsonObject json, String... names) {
        for (String key : names) {
            if (json.has(key) && json.get(key).isJsonPrimitive() && json.get(key).getAsJsonPrimitive().isNumber()) {
                return json.get(key).getAsLong();
            }
        }
        return -1L;
    }
}
