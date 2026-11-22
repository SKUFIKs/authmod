package ru.undermine.authmod.net;

import java.security.GeneralSecurityException;

import javax.annotation.Nullable;
import javax.crypto.SecretKey;

import net.minecraft.client.Minecraft;
import net.neoforged.neoforge.network.PacketDistributor;
import net.neoforged.neoforge.network.handling.IPayloadContext;

import ru.undermine.authmod.AuthMod;
import ru.undermine.authmod.auth.AuthConfig;
import ru.undermine.authmod.auth.LauncherTokenProvider;
import ru.undermine.authmod.client.AccountHints;

/**
 * Client side of the auth flow: answers the configuration handshake with the encrypted
 * token and keeps the negotiated AES key so a token obtained later (/log, /reg or the
 * in-game account screen) can be sent over the same secure channel.
 * Only touched from {@link AuthNetwork} after a client-side distribution check.
 */
public final class ClientAuth {
    private static final byte[] EMPTY = new byte[0];
    private static volatile boolean handshakeCompleted;
    @Nullable
    private static volatile SecretKey sessionKey;

    private ClientAuth() {
    }

    /**
     * True when the server asked for a token during the configuration phase,
     * i.e. the server mod is present and is authoritative for this session.
     */
    public static boolean handshakeCompleted() {
        return handshakeCompleted;
    }

    public static void reset() {
        handshakeCompleted = false;
        sessionKey = null;
    }

    public static void onChallenge(AuthChallengePayload challenge, IPayloadContext context) {
        handshakeCompleted = true;
        boolean knownAccount = knownAccountForLocalPlayer();

        if (challenge.version() != AuthCrypto.PROTOCOL_VERSION) {
            AuthMod.LOGGER.warn("The server uses an unsupported auth handshake version {}", challenge.version());
            context.reply(new AuthTokenPayload(AuthCrypto.PROTOCOL_VERSION, EMPTY, EMPTY, EMPTY, knownAccount));
            return;
        }

        String token = "";
        if (AuthConfig.SEND_TOKEN_TO_SERVERS.get()) {
            LauncherTokenProvider.Found found = LauncherTokenProvider.find().orElse(null);
            if (found == null) {
                AuthMod.LOGGER.warn("The server requested a bearer token, but none is available");
            } else {
                AuthMod.LOGGER.debug("Sending the bearer token from {} to the server (encrypted)", found.source());
                token = found.token();
            }
        }

        try {
            AuthCrypto.EncryptedToken encrypted = AuthCrypto.encryptForServer(
                    challenge.serverPublicKey(), challenge.nonce(), token);
            sessionKey = encrypted.sessionKey();
            context.reply(new AuthTokenPayload(
                    AuthCrypto.PROTOCOL_VERSION,
                    encrypted.clientPublicKey(),
                    encrypted.iv(),
                    encrypted.ciphertext(),
                    knownAccount));
        } catch (GeneralSecurityException | RuntimeException e) {
            AuthMod.LOGGER.error("Could not encrypt the bearer token for the server", e);
            context.reply(new AuthTokenPayload(AuthCrypto.PROTOCOL_VERSION, EMPTY, EMPTY, EMPTY, knownAccount));
        }
    }

    /**
     * Sends a newly obtained token (after /log or /reg) to the current server over the
     * encrypted session channel.
     *
     * @return true when the token was sent; false when there is no server session to use
     */
    public static boolean sendSessionToken(String token) {
        if (!AuthConfig.SEND_TOKEN_TO_SERVERS.get()) {
            return false;
        }

        SecretKey key = sessionKey;
        if (key == null || token == null || token.isBlank()) {
            return false;
        }

        try {
            AuthCrypto.EncryptedMessage message = AuthCrypto.encryptWithKey(key, token);
            PacketDistributor.sendToServer(new AuthSessionPayload(
                    AuthCrypto.PROTOCOL_VERSION, message.iv(), message.ciphertext()));
            return true;
        } catch (GeneralSecurityException | RuntimeException e) {
            AuthMod.LOGGER.error("Could not encrypt the token for the server", e);
            return false;
        }
    }

    /**
     * Tells the server whether this client already knows the account, so reminders can say
     * /log instead of /reg. Purely a display hint.
     */
    public static void sendAccountHint(boolean knownAccount) {
        PacketDistributor.sendToServer(new AuthAccountHintPayload(knownAccount));
    }

    private static boolean knownAccountForLocalPlayer() {
        try {
            return AccountHints.hasAccount(Minecraft.getInstance().getUser().getName());
        } catch (Throwable t) {
            return false;
        }
    }
}
