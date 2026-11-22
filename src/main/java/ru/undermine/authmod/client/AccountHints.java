package ru.undermine.authmod.client;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import net.neoforged.fml.loading.FMLPaths;

import ru.undermine.authmod.AuthMod;
import ru.undermine.authmod.auth.SessionStore;

/**
 * Client-side memory of account names that have successfully logged in or registered
 * on this installation. It is only a hint: the auth API deliberately does not reveal
 * whether an account exists, so a player on a fresh client still gets a /reg prompt
 * with a /log fallback.
 *
 * <p>Stored in {@code config/authmod-accounts.json}.
 */
public final class AccountHints {
    private static final String FILE_NAME = "authmod-accounts.json";
    private static final Set<String> LOGINS = new LinkedHashSet<>();

    private AccountHints() {
    }

    public static synchronized boolean hasAccount(String login) {
        if (login == null || login.isBlank()) {
            return false;
        }
        String normalized = login.trim().toLowerCase(Locale.ROOT);

        Optional<SessionStore.Session> session = SessionStore.load();
        if (session.isPresent() && session.get().login() != null
                && session.get().login().trim().equalsIgnoreCase(normalized)) {
            return true;
        }

        ensureLoaded();
        return LOGINS.contains(normalized);
    }

    public static synchronized void remember(String login) {
        if (login == null || login.isBlank()) {
            return;
        }
        ensureLoaded();
        if (LOGINS.add(login.trim().toLowerCase(Locale.ROOT))) {
            save();
        }
    }

    private static void ensureLoaded() {
        Path path = file();
        if (!Files.isRegularFile(path)) {
            return;
        }
        try {
            JsonObject json = JsonParser.parseString(Files.readString(path, StandardCharsets.UTF_8)).getAsJsonObject();
            if (json.has("logins") && json.get("logins").isJsonArray()) {
                JsonArray logins = json.getAsJsonArray("logins");
                for (JsonElement element : logins) {
                    if (element.isJsonPrimitive()) {
                        String value = element.getAsString();
                        if (!value.isBlank()) {
                            LOGINS.add(value.trim().toLowerCase(Locale.ROOT));
                        }
                    }
                }
            }
        } catch (IOException | RuntimeException e) {
            AuthMod.LOGGER.debug("Could not read account hints: {}", e.toString());
        }
    }

    private static void save() {
        try {
            JsonArray logins = new JsonArray();
            LOGINS.forEach(logins::add);
            JsonObject json = new JsonObject();
            json.add("logins", logins);

            Path path = file();
            Path parent = path.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.writeString(path, json.toString(), StandardCharsets.UTF_8);
        } catch (IOException | RuntimeException e) {
            AuthMod.LOGGER.debug("Could not save account hints: {}", e.toString());
        }
    }

    private static Path file() {
        return FMLPaths.CONFIGDIR.get().resolve(FILE_NAME);
    }
}
