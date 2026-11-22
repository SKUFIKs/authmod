package ru.undermine.authmod.net;

import java.util.function.Consumer;

import net.minecraft.network.Connection;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.resources.ResourceLocation;
import net.minecraft.server.network.ConfigurationTask;
import net.neoforged.neoforge.network.configuration.ICustomConfigurationTask;

import ru.undermine.authmod.AuthMod;

/**
 * Configuration task that runs before the player joins the world: the server sends an
 * ephemeral key, the client answers with the encrypted bearer token and the connection
 * is only allowed to continue after {@link ServerAuth} has validated it.
 */
public final class AuthConfigurationTask implements ICustomConfigurationTask {
    public static final ConfigurationTask.Type TYPE =
            new ConfigurationTask.Type(ResourceLocation.fromNamespaceAndPath(AuthMod.MODID, "authenticate"));

    private final Connection connection;
    private final AuthCrypto.PendingHandshake handshake;

    public AuthConfigurationTask(Connection connection) {
        this.connection = connection;
        this.handshake = AuthCrypto.newHandshake();
    }

    @Override
    public void run(Consumer<CustomPacketPayload> sender) {
        ServerAuth.registerHandshake(connection, handshake);
        sender.accept(new AuthChallengePayload(
                AuthCrypto.PROTOCOL_VERSION,
                handshake.nonce(),
                AuthCrypto.encodedPublicKey(handshake.keyPair())));
    }

    @Override
    public ConfigurationTask.Type type() {
        return TYPE;
    }
}
