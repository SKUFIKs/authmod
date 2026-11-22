package ru.undermine.authmod.auth;

import javax.annotation.Nullable;

/**
 * Resolves the UnderMine API base URL used by the client:
 * the launcher-provided {@code UNDERMINE_API_URL} environment variable wins over
 * the client config, so the launcher and the game always talk to the same API.
 */
public final class ApiEndpoints {
    public static final String DEFAULT_BASE_URL = "https://staging.undermine.click";
    public static final String ENV_API_BASE_URL = "UNDERMINE_API_URL";

    private ApiEndpoints() {
    }

    /**
     * Must be called on the game thread (reads the NeoForge client config).
     */
    public static String baseUrl() {
        String fromLauncher = System.getenv(ENV_API_BASE_URL);
        if (fromLauncher != null && !fromLauncher.isBlank()) {
            return stripTrailingSlash(fromLauncher.trim());
        }
        return stripTrailingSlash(AuthConfig.API_BASE_URL.get().trim());
    }

    public static String loginEndpoint() {
        return AuthConfig.LOGIN_ENDPOINT.get().trim();
    }

    public static String registerEndpoint() {
        return AuthConfig.REGISTER_ENDPOINT.get().trim();
    }

    public static String validateEndpoint() {
        return AuthConfig.VALIDATE_ENDPOINT.get().trim();
    }

    public static int timeoutSeconds() {
        return AuthConfig.HTTP_TIMEOUT_SECONDS.get();
    }

    public static String join(String baseUrl, String endpoint) {
        String base = stripTrailingSlash(baseUrl == null ? "" : baseUrl.trim());
        String path = endpoint == null ? "" : endpoint.trim();
        if (path.startsWith("/")) {
            path = path.substring(1);
        }
        return base + "/" + path;
    }

    public static String stripTrailingSlash(@Nullable String url) {
        if (url == null) {
            return "";
        }
        String trimmed = url.trim();
        while (trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }
}
