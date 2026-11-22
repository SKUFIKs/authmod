package ru.undermine.authmod.net;

import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.codec.ByteBufCodecs;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.resources.ResourceLocation;

import ru.undermine.authmod.AuthMod;

/**
 * Server -&gt; client: ephemeral X25519 public key (X.509 encoded) and nonce for the
 * encrypted token handshake. Sent during the configuration phase, before the player
 * enters the world.
 */
public record AuthChallengePayload(int version, byte[] nonce, byte[] serverPublicKey) implements CustomPacketPayload {
    public static final Type<AuthChallengePayload> TYPE =
            new Type<>(ResourceLocation.fromNamespaceAndPath(AuthMod.MODID, "auth_challenge"));

    public static final StreamCodec<FriendlyByteBuf, AuthChallengePayload> STREAM_CODEC = StreamCodec.composite(
            ByteBufCodecs.VAR_INT, AuthChallengePayload::version,
            ByteBufCodecs.byteArray(AuthCrypto.MAX_NONCE), AuthChallengePayload::nonce,
            ByteBufCodecs.byteArray(AuthCrypto.MAX_PUBLIC_KEY), AuthChallengePayload::serverPublicKey,
            AuthChallengePayload::new);

    @Override
    public Type<AuthChallengePayload> type() {
        return TYPE;
    }
}
