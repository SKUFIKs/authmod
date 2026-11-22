package ru.undermine.authmod.net;

import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.resources.ResourceLocation;

import ru.undermine.authmod.AuthMod;

/**
 * Client -&gt; server (play phase): updates the "account exists" hint after the client
 * learns it from the auth API (e.g. /reg answered USERNAME_TAKEN). Only affects which
 * prompt (/log or /reg) is shown to the player.
 */
public record AuthAccountHintPayload(boolean knownAccount) implements CustomPacketPayload {
    public static final Type<AuthAccountHintPayload> TYPE =
            new Type<>(ResourceLocation.fromNamespaceAndPath(AuthMod.MODID, "account_hint"));

    public static final StreamCodec<FriendlyByteBuf, AuthAccountHintPayload> STREAM_CODEC = StreamCodec.of(
            (buffer, payload) -> buffer.writeBoolean(payload.knownAccount()),
            buffer -> new AuthAccountHintPayload(buffer.readBoolean()));

    @Override
    public Type<AuthAccountHintPayload> type() {
        return TYPE;
    }
}
