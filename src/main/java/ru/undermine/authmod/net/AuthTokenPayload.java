package ru.undermine.authmod.net;

import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.codec.ByteBufCodecs;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.resources.ResourceLocation;

import ru.undermine.authmod.AuthMod;

/**
 * Client -&gt; server: the bearer token encrypted with the server's ephemeral key
 * (ECDH X25519 + HKDF-SHA256 + AES-256-GCM). An empty token means the launcher did
 * not provide one. {@code knownAccount} is a client-side hint used to choose between
 * the /log and /reg prompts (the API does not reveal account existence).
 */
public record AuthTokenPayload(int version, byte[] clientPublicKey, byte[] iv, byte[] ciphertext,
                               boolean knownAccount) implements CustomPacketPayload {
    public static final Type<AuthTokenPayload> TYPE =
            new Type<>(ResourceLocation.fromNamespaceAndPath(AuthMod.MODID, "auth_token"));

    public static final StreamCodec<FriendlyByteBuf, AuthTokenPayload> STREAM_CODEC = StreamCodec.composite(
            ByteBufCodecs.VAR_INT, AuthTokenPayload::version,
            ByteBufCodecs.byteArray(AuthCrypto.MAX_PUBLIC_KEY), AuthTokenPayload::clientPublicKey,
            ByteBufCodecs.byteArray(AuthCrypto.IV_LENGTH), AuthTokenPayload::iv,
            ByteBufCodecs.byteArray(AuthCrypto.MAX_CIPHERTEXT), AuthTokenPayload::ciphertext,
            ByteBufCodecs.BOOL, AuthTokenPayload::knownAccount,
            AuthTokenPayload::new);

    @Override
    public Type<AuthTokenPayload> type() {
        return TYPE;
    }
}
