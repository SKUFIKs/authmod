package ru.undermine.authmod.net;

import net.minecraft.network.chat.Component;
import net.minecraft.network.protocol.configuration.ServerConfigurationPacketListener;
import net.neoforged.fml.loading.FMLEnvironment;
import net.neoforged.neoforge.network.event.RegisterConfigurationTasksEvent;
import net.neoforged.neoforge.network.event.RegisterPayloadHandlersEvent;
import net.neoforged.neoforge.network.handling.IPayloadContext;
import net.neoforged.neoforge.network.registration.PayloadRegistrar;

import ru.undermine.authmod.AuthMod;
import ru.undermine.authmod.auth.AuthServerConfig;

/**
 * Registers the authentication payloads (configuration phase) and the configuration
 * task that gates the connection until the bearer token is validated.
 */
public final class AuthNetwork {
    private static final String PROTOCOL_VERSION = "2";

    private AuthNetwork() {
    }

    public static void registerPayloads(RegisterPayloadHandlersEvent event) {
        PayloadRegistrar registrar = event.registrar(PROTOCOL_VERSION);
        registrar.configurationToClient(
                AuthChallengePayload.TYPE,
                AuthChallengePayload.STREAM_CODEC,
                AuthNetwork::handleChallenge);
        registrar.configurationToServer(
                AuthTokenPayload.TYPE,
                AuthTokenPayload.STREAM_CODEC,
                ServerAuth::handleToken);
        // /log and /reg send a token obtained after the player is already in the world.
        registrar.playToServer(
                AuthSessionPayload.TYPE,
                AuthSessionPayload.STREAM_CODEC,
                ServerAuth::handleSessionToken);
        registrar.playToServer(
                AuthAccountHintPayload.TYPE,
                AuthAccountHintPayload.STREAM_CODEC,
                ServerAuth::handleAccountHint);
    }

    public static void registerConfigurationTasks(RegisterConfigurationTasksEvent event) {
        if (!AuthServerConfig.ENABLED.get()) {
            return;
        }

        ServerConfigurationPacketListener listener = event.getListener();
        boolean clientHasMod = listener.hasChannel(AuthChallengePayload.TYPE)
                && listener.hasChannel(AuthTokenPayload.TYPE);

        if (clientHasMod) {
            event.register(new AuthConfigurationTask(listener.getConnection()));
            return;
        }

        if (!AuthServerConfig.ALLOW_CLIENTS_WITHOUT_MOD.get()) {
            AuthMod.LOGGER.warn("Rejecting a client that does not have the UnderMine Auth mod installed");
            listener.getConnection().disconnect(Component.translatable("message.authmod.server_client_missing_mod"));
        }
    }

    private static void handleChallenge(AuthChallengePayload payload, IPayloadContext context) {
        // Client only: encrypt the launcher/session token for this server.
        if (FMLEnvironment.dist.isClient()) {
            ClientAuth.onChallenge(payload, context);
        }
    }
}

