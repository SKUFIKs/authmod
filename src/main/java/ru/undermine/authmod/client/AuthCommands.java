package ru.undermine.authmod.client;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.arguments.StringArgumentType;

import net.minecraft.client.Minecraft;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.Commands;
import net.minecraft.network.chat.Component;

import ru.undermine.authmod.AuthMod;
import ru.undermine.authmod.auth.AuthApiClient;
import ru.undermine.authmod.auth.DeviceIdProvider;
import ru.undermine.authmod.auth.SessionStore;
import ru.undermine.authmod.net.ClientAuth;
/**
 * Client-side /log and /reg commands.
 *
 * <p>They are handled locally by the client, so the password goes only to the UnderMine
 * API over HTTPS and never to the game server or its logs. On success the token is stored
 * for future sessions and, when the server supports authmod, sent over the encrypted
 * session channel.
 */
public final class AuthCommands {
    private static final long COOLDOWN_MILLIS = 1500L;
    private static long lastAttempt;

    private AuthCommands() {
    }

    public static void register(CommandDispatcher<CommandSourceStack> dispatcher) {
        dispatcher.register(Commands.literal("log")
                .then(Commands.argument("password", StringArgumentType.greedyString())
                        .executes(context -> {
                            login(StringArgumentType.getString(context, "password"));
                            return 1;
                        })));

        dispatcher.register(Commands.literal("reg")
                .then(Commands.argument("password", PasswordArgument.password())
                        .then(Commands.argument("confirmation", PasswordArgument.password())
                                .executes(context -> {
                                    register(
                                            PasswordArgument.getPassword(context, "password"),
                                            PasswordArgument.getPassword(context, "confirmation"));
                                    return 1;
                                }))));
    }

    private static void login(String password) {
        Minecraft minecraft = Minecraft.getInstance();
        if (minecraft.player == null || minecraft.getConnection() == null) {
            message(Component.translatable("authmod.auth.command.no_server"));
            return;
        }
        if (password == null || password.isBlank()) {
            message(Component.translatable("authmod.auth.command.usage_log"));
            return;
        }
        if (!cooldown()) {
            return;
        }

        String login = minecraft.player.getGameProfile().getName();
        message(Component.translatable("authmod.auth.command.working"));
        AuthApiClient.loginAsync(login, password).whenComplete((response, error) ->
                minecraft.execute(() -> onResult(login, response, error, false)));
    }

    private static void register(String password, String confirmation) {
        Minecraft minecraft = Minecraft.getInstance();
        if (minecraft.player == null || minecraft.getConnection() == null) {
            message(Component.translatable("authmod.auth.command.no_server"));
            return;
        }
        if (password == null || password.isBlank() || confirmation == null || confirmation.isBlank()) {
            message(Component.translatable("authmod.auth.command.usage_reg"));
            return;
        }
        if (!password.equals(confirmation)) {
            message(Component.translatable("authmod.auth.command.password_mismatch"));
            return;
        }

        int passwordBytes = password.getBytes(StandardCharsets.UTF_8).length;
        if (password.length() < 8 || passwordBytes > 72) {
            message(Component.translatable("authmod.auth.command.password_policy"));
            return;
        }
        if (!cooldown()) {
            return;
        }

        String login = minecraft.player.getGameProfile().getName();
        message(Component.translatable("authmod.auth.command.working"));
        AuthApiClient.registerAsync(login, password, DeviceIdProvider.get()).whenComplete((response, error) ->
                minecraft.execute(() -> onResult(login, response, error, true)));
    }

    private static boolean cooldown() {
        long now = System.currentTimeMillis();
        if (now - lastAttempt < COOLDOWN_MILLIS) {
            message(Component.translatable("authmod.auth.command.too_fast"));
            return false;
        }
        lastAttempt = now;
        return true;
    }

    private static void onResult(String attemptedLogin, AuthApiClient.AuthResponse response, Throwable error, boolean registration) {
        if (error != null) {
            AuthMod.LOGGER.warn("In-game authentication request failed", error);
            message(Component.translatable("authmod.auth.command.failed",
                    error.getMessage() == null ? error.toString() : error.getMessage()));
            return;
        }

        if (response == null || !response.success()) {
            String reason = response == null || response.message() == null || response.message().isBlank()
                    ? "unknown error"
                    : response.message();

            if (!registration && response != null && response.status() == 401) {
                message(Component.translatable("authmod.auth.command.login_failed_hint", reason));
                return;
            }

            if (registration && response != null
                    && (response.status() == 409 || "USERNAME_TAKEN".equalsIgnoreCase(response.errorCode()))) {
                // The API only reveals this through a registration conflict; remember it so
                // the limbo reminder switches from /reg to /log.
                AccountHints.remember(attemptedLogin);
                ClientAuth.sendAccountHint(true);
                message(Component.translatable("authmod.auth.command.register_exists"));
                return;
            }

            message(Component.translatable("authmod.auth.command.failed", reason));
            return;
        }

        try {
            SessionStore.save(response.token(), response.login(), response.userId());
        } catch (IOException e) {
            AuthMod.LOGGER.warn("Could not save the session", e);
            message(Component.translatable("authmod.auth.command.save_failed", String.valueOf(e.getMessage())));
            return;
        }

        String name = response.login() == null || response.login().isBlank()
                ? attemptedLogin
                : response.login();
        AccountHints.remember(name);

        if (ClientAuth.sendSessionToken(response.token())) {
            message(Component.translatable(
                    registration ? "authmod.auth.command.registered" : "authmod.auth.command.waiting", name));
        } else {
            message(Component.translatable("authmod.auth.command.saved_reconnect", name));
        }
    }

    private static void message(Component component) {
        Minecraft minecraft = Minecraft.getInstance();
        if (minecraft.player != null) {
            minecraft.player.sendSystemMessage(component);
        } else if (minecraft.gui != null) {
            minecraft.gui.getChat().addMessage(component);
        }
    }
}
