package ru.undermine.authmod.auth;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Instant;
import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import net.neoforged.fml.loading.FMLPaths;

/**
 * Stores the token obtained from the in-game login screen so it can be reused
 * for later sessions without the launcher.
 *
 * <p>The file lives in {@code config/authmod-session.json}. On POSIX systems it is
 * created with {@code 600} permissions; on Windows it inherits the user profile ACL.
 */
public final class SessionStore {
    private static final Gson GSON = new Gson();
    private static final String FILE_NAME = "authmod-session.json";

    private SessionStore() {
    }

    public record Session(String token, String login, long userId, long savedAt) {
    }

    private static Path file() {
        return FMLPaths.CONFIGDIR.get().resolve(FILE_NAME);
    }

    public static Optional<Session> load() {
        Path path = file();
        if (!Files.isRegularFile(path)) {
            return Optional.empty();
        }
        try {
            String raw = Files.readString(path, StandardCharsets.UTF_8);
            JsonObject json = JsonParser.parseString(raw).getAsJsonObject();
            String token = optString(json, "token");
            if (token == null || token.isBlank()) {
                return Optional.empty();
            }
            return Optional.of(new Session(
                    token,
                    optStringOr(json, "login", ""),
                    optLong(json, "userId"),
                    optLong(json, "savedAt")));
        } catch (IOException | RuntimeException e) {
            return Optional.empty();
        }
    }

    public static boolean hasSession() {
        return load().isPresent();
    }

    public static void save(String token, String login, long userId) throws IOException {
        JsonObject json = new JsonObject();
        json.addProperty("token", token);
        json.addProperty("login", login == null ? "" : login);
        json.addProperty("userId", userId);
        json.addProperty("savedAt", Instant.now().toEpochMilli());

        Path path = file();
        Path parent = path.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }

        Path tmp = path.resolveSibling(FILE_NAME + ".tmp");
        Files.writeString(tmp, GSON.toJson(json), StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
        try {
            Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING);
        }
        restrictPermissions(path);
    }

    public static void clear() {
        try {
            Files.deleteIfExists(file());
        } catch (IOException ignored) {
            // The file may be locked; the token will be replaced on the next save.
        }
    }

    private static void restrictPermissions(Path path) {
        try {
            if (Files.getFileStore(path).supportsFileAttributeView("posix")) {
                Set<PosixFilePermission> ownerOnly = EnumSet.of(
                        PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE);
                Files.setPosixFilePermissions(path, ownerOnly);
            }
        } catch (IOException | UnsupportedOperationException ignored) {
            // Best effort: keep the file writeable for the current user.
        }
    }

    private static String optString(JsonObject json, String key) {
        if (json.has(key) && json.get(key).isJsonPrimitive()) {
            return json.get(key).getAsString();
        }
        return null;
    }

    private static String optStringOr(JsonObject json, String key, String fallback) {
        String value = optString(json, key);
        return value == null ? fallback : value;
    }

    private static long optLong(JsonObject json, String key) {
        if (json.has(key) && json.get(key).isJsonPrimitive()) {
            try {
                return json.get(key).getAsLong();
            } catch (RuntimeException ignored) {
            }
        }
        return 0L;
    }
}
