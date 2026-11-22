package ru.undermine.authmod.auth;

import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

import javax.annotation.Nullable;

import net.minecraft.client.Minecraft;

import ru.undermine.authmod.AuthMod;

/**
 * Locates the bearer token supplied by the UnderMine launcher.
 * The launcher currently passes the JWT through the standard Minecraft
 * {@code --accessToken} (or {@code --authSession}) game argument, and may also
 * provide it via the {@code UNDERMINE_AUTH_TOKEN} environment variable.
 *
 * <p>Search order:
 * <ol>
 *   <li>system property {@code authmod.token} (for development/run configs),</li>
 *   <li>environment variable {@code UNDERMINE_AUTH_TOKEN},</li>
 *   <li>game process arguments ({@code --accessToken &lt;jwt&gt;} and friends),</li>
 *   <li>the vanilla session ({@code token:&lt;jwt&gt;:&lt;uuid&gt;}) in the client options.</li>
 * </ol>
 */
public final class LauncherTokenProvider {
    /** Development-only override. */
    public static final String DEV_SYS_PROPERTY = "authmod.token";
    /** Environment variable the launcher can use to pass the token. */
    public static final String ENV_VARIABLE = "UNDERMINE_AUTH_TOKEN";

    /** Argument keys (normalized) that are known to carry the token, e.g. {@code --accessToken}. */
    private static final Set<String> ARGUMENT_KEYS = Set.of(
            "accesstoken",
            "authaccesstoken",
            "authsession",
            "logintoken",
            "token");

    /** A token shorter than this is considered a placeholder (e.g. vanilla's "0"). */
    private static final int MIN_TOKEN_LENGTH = 32;

    private LauncherTokenProvider() {
    }

    /**
     * Where the token was found and the token itself. {@code source} is used for logs only.
     */
    public record Found(String token, String source) {
    }

    public static Optional<Found> find() {
        return fromSystemProperty()
                .or(LauncherTokenProvider::fromEnvironment)
                .or(LauncherTokenProvider::fromProcessArguments)
                .or(LauncherTokenProvider::fromSavedSession)
                .or(LauncherTokenProvider::fromMinecraftSession);
    }

    public static Optional<String> findToken() {
        return find().map(Found::token);
    }

    private static Optional<Found> fromSystemProperty() {
        return clean(System.getProperty(DEV_SYS_PROPERTY), "system property " + DEV_SYS_PROPERTY);
    }

    private static Optional<Found> fromEnvironment() {
        return clean(System.getenv(ENV_VARIABLE), "environment variable " + ENV_VARIABLE);
    }

    private static Optional<Found> fromProcessArguments() {
        String[] argumentsArray = ProcessHandle.current().info().arguments().orElse(null);
        if (argumentsArray == null) {
            return Optional.empty();
        }
        List<String> arguments = List.of(argumentsArray);
        for (int i = 0; i < arguments.size(); i++) {
            String argument = arguments.get(i);
            if (argument == null) {
                continue;
            }
            String key = normalizeKey(argument);
            if (!ARGUMENT_KEYS.contains(key)) {
                continue;
            }
            String value = null;
            int equals = argument.indexOf('=');
            if (equals >= 0 && equals < argument.length() - 1) {
                value = argument.substring(equals + 1);
            } else if (i + 1 < arguments.size()) {
                value = arguments.get(i + 1);
            }
            if (looksLikeJwt(value)) {
                return clean(value, "game argument --" + key);
            }
        }
        return Optional.empty();
    }

    /**
     * Token saved by the in-game login screen. Used when the game was started without
     * the launcher (or the launcher did not pass a token).
     */
    private static Optional<Found> fromSavedSession() {
        return SessionStore.load()
                .filter(session -> looksLikeJwt(session.token()))
                .map(session -> new Found(session.token(), "saved in-game session"));
    }

    /**
     * Fallback: vanilla stores the access token in {@code User#getSessionId()}
     * in the {@code token:<accessToken>:<uuid>} format when the game was launched
     * with {@code --accessToken}. Only meaningful on the client.
     */
    private static Optional<Found> fromMinecraftSession() {
        try {
            String sessionId = Minecraft.getInstance().getUser().getSessionId();
            if (sessionId == null || !sessionId.startsWith("token:")) {
                return Optional.empty();
            }
            String[] parts = sessionId.split(":", 3);
            if (parts.length == 3 && looksLikeJwt(parts[1])) {
                return clean(parts[1], "minecraft session");
            }
        } catch (Throwable t) {
            AuthMod.LOGGER.debug("Session fallback is unavailable: {}", t.toString());
        }
        return Optional.empty();
    }

    private static String normalizeKey(String argument) {
        String s = argument.toLowerCase(Locale.ROOT);
        int start = 0;
        while (start < s.length() && s.charAt(start) == '-') {
            start++;
        }
        s = s.substring(start);
        int equals = s.indexOf('=');
        if (equals >= 0) {
            s = s.substring(0, equals);
        }
        return s.replace("_", "").replace(".", "");
    }

    private static boolean looksLikeJwt(@Nullable String value) {
        return value != null
                && value.trim().length() >= MIN_TOKEN_LENGTH
                && value.indexOf('.') >= 0
                && !value.contains(" ");
    }

    private static Optional<Found> clean(@Nullable String token, String source) {
        if (token == null || token.isBlank()) {
            return Optional.empty();
        }
        return Optional.of(new Found(token.trim(), source));
    }
}
