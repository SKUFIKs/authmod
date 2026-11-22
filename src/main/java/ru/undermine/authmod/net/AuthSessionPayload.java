package ru.undermine.authmod.net;

import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.codec.ByteBufCodecs;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.resources.ResourceLocation;

import ru.undermine.authmod.AuthMod;

/**
 * Client -&gt; server (play phase): a token obtained with {@code /log} or {@code /reg},
 * encrypted with the AES key established during the configuration handshake.
 */
public record AuthSessionPayload(int version, byte[] iv, byte[] ciphertext) implements CustomPacketPayload {
    public static final Type<AuthSessionPayload> TYPE =
            new Type<>(ResourceLocation.fromNamespaceAndPath(AuthMod.MODID, "auth_session"));

    public static final StreamCodec<FriendlyByteBuf, AuthSessionPayload> STREAM_CODEC = StreamCodec.composite(
            ByteBufCodecs.VAR_INT, AuthSessionPayload::version,
            ByteBufCodecs.byteArray(AuthCrypto.IV_LENGTH), AuthSessionPayload::iv,
            ByteBufCodecs.byteArray(AuthCrypto.MAX_CIPHERTEXT), AuthSessionPayload::ciphertext,
            AuthSessionPayload::new);

    @Override
    public Type<AuthSessionPayload> type() {
        return TYPE;
    }
}
