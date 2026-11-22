package ru.undermine.authmod.net;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class AuthCryptoTest {
    @Test
    void roundTripsTheToken() throws Exception {
        AuthCrypto.PendingHandshake server = AuthCrypto.newHandshake();
        byte[] serverPublicKey = AuthCrypto.encodedPublicKey(server.keyPair());

        AuthCrypto.EncryptedToken encrypted = AuthCrypto.encryptForServer(
                serverPublicKey, server.nonce(), "header.payload.signature");

        AuthCrypto.DecryptedToken decrypted = AuthCrypto.decryptFromClient(
                server, encrypted.clientPublicKey(), encrypted.iv(), encrypted.ciphertext());

        assertNotNull(decrypted);
        assertEquals("header.payload.signature", decrypted.token());
        assertNotNull(decrypted.sessionKey());
    }

    @Test
    void roundTripsAnEmptyToken() throws Exception {
        AuthCrypto.PendingHandshake server = AuthCrypto.newHandshake();
        AuthCrypto.EncryptedToken encrypted = AuthCrypto.encryptForServer(
                AuthCrypto.encodedPublicKey(server.keyPair()), server.nonce(), "");

        AuthCrypto.DecryptedToken decrypted = AuthCrypto.decryptFromClient(
                server, encrypted.clientPublicKey(), encrypted.iv(), encrypted.ciphertext());

        assertNotNull(decrypted);
        assertEquals("", decrypted.token());
    }

    @Test
    void rejectsCiphertextFromAnotherHandshake() throws Exception {
        AuthCrypto.PendingHandshake server = AuthCrypto.newHandshake();
        AuthCrypto.PendingHandshake other = AuthCrypto.newHandshake();

        AuthCrypto.EncryptedToken encrypted = AuthCrypto.encryptForServer(
                AuthCrypto.encodedPublicKey(server.keyPair()), server.nonce(), "token");

        assertNull(AuthCrypto.decryptFromClient(
                other, encrypted.clientPublicKey(), encrypted.iv(), encrypted.ciphertext()));
    }

    @Test
    void rejectsTamperedCiphertext() throws Exception {
        AuthCrypto.PendingHandshake server = AuthCrypto.newHandshake();
        AuthCrypto.EncryptedToken encrypted = AuthCrypto.encryptForServer(
                AuthCrypto.encodedPublicKey(server.keyPair()), server.nonce(), "token");

        byte[] tampered = encrypted.ciphertext().clone();
        tampered[0] ^= 0x01;

        assertNull(AuthCrypto.decryptFromClient(server, encrypted.clientPublicKey(), encrypted.iv(), tampered));
    }

    @Test
    void rejectsMalformedPayload() {
        AuthCrypto.PendingHandshake server = AuthCrypto.newHandshake();

        assertNull(AuthCrypto.decryptFromClient(server, new byte[0], new byte[12], new byte[24]));
        assertNull(AuthCrypto.decryptFromClient(server, new byte[44], new byte[3], new byte[24]));
    }

    @Test
    void sessionKeyEncryptsLaterMessages() throws Exception {
        AuthCrypto.PendingHandshake server = AuthCrypto.newHandshake();
        AuthCrypto.EncryptedToken encrypted = AuthCrypto.encryptForServer(
                AuthCrypto.encodedPublicKey(server.keyPair()), server.nonce(), "initial");
        AuthCrypto.DecryptedToken decrypted = AuthCrypto.decryptFromClient(
                server, encrypted.clientPublicKey(), encrypted.iv(), encrypted.ciphertext());
        assertNotNull(decrypted);

        // The client keeps its derived key; the server keeps its copy from decryption.
        AuthCrypto.EncryptedMessage message = AuthCrypto.encryptWithKey(encrypted.sessionKey(), "later-token");

        assertEquals("later-token", AuthCrypto.decryptWithKey(decrypted.sessionKey(), message.iv(), message.ciphertext()));
    }

    @Test
    void sessionKeyRejectsTampering() throws Exception {
        AuthCrypto.PendingHandshake server = AuthCrypto.newHandshake();
        AuthCrypto.EncryptedToken encrypted = AuthCrypto.encryptForServer(
                AuthCrypto.encodedPublicKey(server.keyPair()), server.nonce(), "initial");
        AuthCrypto.DecryptedToken decrypted = AuthCrypto.decryptFromClient(
                server, encrypted.clientPublicKey(), encrypted.iv(), encrypted.ciphertext());
        assertNotNull(decrypted);

        AuthCrypto.EncryptedMessage message = AuthCrypto.encryptWithKey(encrypted.sessionKey(), "later-token");
        byte[] tampered = message.ciphertext().clone();
        tampered[tampered.length - 1] ^= 0x01;

        assertNull(AuthCrypto.decryptWithKey(decrypted.sessionKey(), message.iv(), tampered));
    }
}
