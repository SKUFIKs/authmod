package ru.undermine.authmod.auth;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.UUID;
import java.util.regex.Pattern;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import net.neoforged.fml.loading.FMLPaths;

/**
 * Stable identifier sent as {@code deviceID} when registering from inside the game.
 * The API requires 16–128 characters from {@code [A-Za-z0-9._:-]}; a SHA-256 hex
 * digest of a random id persisted in {@code config/authmod-device.json} is used.
 */
public final class DeviceIdProvider {
    /** The launcher can pass its own hashed device id through this variable. */
    public static final String ENV_DEVICE_ID = "UNDERMINE_DEVICE_ID";

    private static final Pattern VALID = Pattern.compile("^[A-Za-z0-9._:-]{16,128}$");
    private static final String FILE_NAME = "authmod-device.json";
    private static String cached;

    private DeviceIdProvider() {
    }

    public static synchronized String get() {
        if (cached != null) {
            return cached;
        }

        String fromLauncher = System.getenv(ENV_DEVICE_ID);
        if (fromLauncher != null && VALID.matcher(fromLauncher.trim()).matches()) {
            cached = fromLauncher.trim();
            return cached;
        }

        String id = loadOrCreateId();
        cached = sha256Hex(id);
        return cached;
    }

    private static String loadOrCreateId() {
        Path path = FMLPaths.CONFIGDIR.get().resolve(FILE_NAME);
        try {
            if (Files.isRegularFile(path)) {
                JsonObject json = JsonParser.parseString(Files.readString(path, StandardCharsets.UTF_8)).getAsJsonObject();
                if (json.has("id") && json.get("id").isJsonPrimitive()) {
                    String id = json.get("id").getAsString();
                    if (!id.isBlank()) {
                        return id;
                    }
                }
            }

            String id = UUID.randomUUID().toString();
            JsonObject json = new JsonObject();
            json.addProperty("id", id);
            Path parent = path.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.writeString(path, json.toString(), StandardCharsets.UTF_8);
            return id;
        } catch (IOException | RuntimeException e) {
            // Last resort: a per-process id. Registration still works, it just is not stable.
            return UUID.randomUUID().toString();
        }
    }

    private static String sha256Hex(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            return value;
        }
    }
}
