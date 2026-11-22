package ru.undermine.authmod;

import javax.annotation.Nullable;

import net.minecraft.ChatFormatting;
import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.screens.PauseScreen;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.client.gui.screens.TitleScreen;
import net.minecraft.network.Connection;
import net.minecraft.network.chat.Component;
import net.minecraft.network.chat.MutableComponent;

import net.neoforged.api.distmarker.Dist;
import net.neoforged.bus.api.SubscribeEvent;
import net.neoforged.fml.ModContainer;
import net.neoforged.fml.common.EventBusSubscriber;
import net.neoforged.fml.common.Mod;
import net.neoforged.fml.event.lifecycle.FMLClientSetupEvent;
import net.neoforged.neoforge.client.event.ClientPlayerNetworkEvent;
import net.neoforged.neoforge.client.event.RegisterClientCommandsEvent;
import net.neoforged.neoforge.client.event.ScreenEvent;
import net.neoforged.neoforge.client.gui.ConfigurationScreen;
import net.neoforged.neoforge.client.gui.IConfigScreenFactory;

import ru.undermine.authmod.auth.AuthConfig;
import ru.undermine.authmod.auth.AuthGuard;
import ru.undermine.authmod.auth.TokenInfo;
import ru.undermine.authmod.auth.TokenValidator;
import ru.undermine.authmod.client.AuthCommands;
import ru.undermine.authmod.client.gui.AuthScreen;
import ru.undermine.authmod.net.ClientAuth;

/**
 * Client entry point. When the server has the mod, it validates the token during the
 * configuration phase and this class only reports the result. For servers without the
 * mod the token is checked locally (presence, expiry) and against the API on join.
 */
@Mod(value = AuthMod.MODID, dist = Dist.CLIENT)
@EventBusSubscriber(modid = AuthMod.MODID, value = Dist.CLIENT)
public class AuthModClient {
    public AuthModClient(ModContainer container) {
        container.registerExtensionPoint(IConfigScreenFactory.class, ConfigurationScreen::new);
    }

    @SubscribeEvent
    static void onClientSetup(FMLClientSetupEvent event) {
        AuthGuard.Check check = AuthGuard.check();
        if (!check.ok() || check.found() == null || check.info() == null) {
            AuthMod.LOGGER.info("No usable bearer token from the launcher");
            return;
        }
        TokenInfo info = check.info();
        AuthMod.LOGGER.info("Bearer token found in the {} (player: {}, role: {}, valid until: {})",
                check.found().source(), info.name(), info.role(), info.formattedExpiry());
    }

    @SubscribeEvent
    static void onLoggingIn(ClientPlayerNetworkEvent.LoggingIn event) {
        // Singleplayer and the LAN host must never be locked out by the client-side checks.
        if (Minecraft.getInstance().hasSingleplayerServer()) {
            return;
        }

        AuthGuard.Check check = AuthGuard.check();

        // The server mod asked for and validated the token during the configuration phase;
        // it is the authority for this session.
        if (ClientAuth.handshakeCompleted()) {
            if (check.ok() && check.info() != null && AuthConfig.NOTIFY_ON_JOIN.get()) {
                notifyJoin(check.info());
            }
            return;
        }

        if (!check.ok()) {
            AuthMod.LOGGER.warn("Joining rejected: token check failed locally, disconnecting");
            event.getConnection().disconnect(check.failure());
            return;
        }
        if (check.found() == null) {
            return; // no token available and requireToken=false
        }
        scheduleRemoteValidation(event.getConnection(), check);
    }

    @SubscribeEvent
    static void onLoggingOut(ClientPlayerNetworkEvent.LoggingOut event) {
        ClientAuth.reset();
    }

    /**
     * Registers the local /log and /reg commands. They are executed on the client and are
     * never sent to the server, so passwords do not end up in server logs.
     */
    @SubscribeEvent
    static void onRegisterClientCommands(RegisterClientCommandsEvent event) {
        AuthCommands.register(event.getDispatcher());
    }

    /**
     * Adds the account button to the title screen and the pause menu.
     */
    @SubscribeEvent
    static void onScreenInit(ScreenEvent.Init.Post event) {
        Screen screen = event.getScreen();
        if (!(screen instanceof TitleScreen) && !(screen instanceof PauseScreen)) {
            return;
        }

        event.addListener(Button.builder(
                        Component.translatable("authmod.button.account"),
                        button -> Minecraft.getInstance().setScreen(new AuthScreen(screen)))
                .bounds(screen.width - 124, screen.height - 24, 120, 20)
                .build());
    }

    private static void scheduleRemoteValidation(Connection connection, AuthGuard.Check check) {
        TokenInfo info = check.info();
        if (info == null) {
            return;
        }
        TokenValidator.validateAsync(info.token()).whenComplete((result, error) ->
                Minecraft.getInstance().execute(() -> {
                    if (error != null) {
                        AuthMod.LOGGER.error("Token validation failed unexpectedly", error);
                        onValidationFinished(connection, new TokenValidator.Result(
                                TokenValidator.Outcome.ERROR, String.valueOf(error), ""), check);
                        return;
                    }
                    onValidationFinished(connection, result, check);
                }));
    }

    private static void onValidationFinished(@Nullable Connection connection, TokenValidator.Result result, AuthGuard.Check check) {
        String detail = result.errorCode() == null || result.errorCode().isBlank()
                ? result.message()
                : result.errorCode() + ": " + result.message();

        switch (result.outcome()) {
            case INVALID -> {
                AuthMod.LOGGER.warn("The API rejected the bearer token: {}", detail);
                if (AuthConfig.DISCONNECT_WHEN_INVALID.get()) {
                    disconnect(connection, Component.translatable("message.authmod.token_invalid", detail));
                }
            }
            case ERROR -> {
                AuthMod.LOGGER.warn("The token could not be validated: {}", result.message());
                if (AuthConfig.DISCONNECT_ON_VALIDATION_ERROR.get()) {
                    disconnect(connection, Component.translatable("message.authmod.validation_unavailable", result.message()));
                }
            }
            case VALID -> {
                TokenInfo info = check.info();
                AuthMod.LOGGER.info("The API accepted the bearer token for {}", info == null ? null : info.name());
                if (AuthConfig.NOTIFY_ON_JOIN.get() && info != null) {
                    notifyJoin(info);
                }
            }
        }
    }

    private static void notifyJoin(TokenInfo info) {
        Minecraft minecraft = Minecraft.getInstance();
        if (minecraft.gui == null || minecraft.player == null) {
            return;
        }
        minecraft.gui.getChat().addMessage(joinMessage(info).withStyle(ChatFormatting.GREEN));
    }

    private static MutableComponent joinMessage(TokenInfo info) {
        String name = info.name() == null ? "?" : info.name();
        if (info.hasExpiry()) {
            return Component.translatable("message.authmod.join_validated", name, info.formattedExpiry());
        }
        return Component.translatable("message.authmod.join_validated_no_expiry", name);
    }

    private static void disconnect(@Nullable Connection connection, Component reason) {
        if (connection != null && connection.isConnected()) {
            connection.disconnect(reason);
        } else {
            // The connection is already gone; return to the main menu as a fallback.
            Minecraft.getInstance().disconnect();
        }
    }
}
