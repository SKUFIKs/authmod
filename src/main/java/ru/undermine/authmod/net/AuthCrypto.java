package ru.undermine.authmod.net;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.annotation.Nullable;

/**
 * End-to-end encryption for the token handshake.
 *
 * <p>The server sends an ephemeral X25519 public key and a random nonce; the client generates
 * its own ephemeral X25519 key pair, derives a shared secret (ECDH) and encrypts the token with
 * AES-256-GCM (HKDF-SHA256 for key derivation). The token therefore never travels over the
 * game connection in plain text.
 *
 * <p>This protects against passive traffic capture. Minecraft's offline-mode protocol has no
 * authenticated server identity, so an active man-in-the-middle is out of scope (such a server
 * could also simply ask for the password).
 */
public final class AuthCrypto {
    public static final int PROTOCOL_VERSION = 2;

    public static final int NONCE_LENGTH = 16;
    public static final int IV_LENGTH = 12;
    public static final int MAX_NONCE = 32;
    public static final int MAX_PUBLIC_KEY = 256;
    public static final int MAX_CIPHERTEXT = 16 * 1024;

    private static final int AES_KEY_BITS = 256;
    private static final byte[] HKDF_INFO = "authmod/token/v1".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    private static final SecureRandom RANDOM = new SecureRandom();

    private AuthCrypto() {
    }

    public record PendingHandshake(KeyPair keyPair, byte[] nonce) {
    }

    public record EncryptedToken(byte[] clientPublicKey, byte[] iv, byte[] ciphertext, SecretKey sessionKey) {
    }

    public record DecryptedToken(String token, SecretKey sessionKey) {
    }

    public record EncryptedMessage(byte[] iv, byte[] ciphertext) {
    }

    public static PendingHandshake newHandshake() {
        return new PendingHandshake(generateKeyPair(), randomBytes(NONCE_LENGTH));
    }

    public static byte[] encodedPublicKey(KeyPair keyPair) {
        return keyPair.getPublic().getEncoded();
    }

    /**
     * Client side: encrypt the token (may be empty) for the server's ephemeral key.
     */
    public static EncryptedToken encryptForServer(byte[] serverPublicKey, byte[] nonce, String token) throws GeneralSecurityException {
        KeyPair clientKeyPair = generateKeyPair();
        byte[] clientPublicKey = encodedPublicKey(clientKeyPair);

        SecretKey key = deriveKey(
                clientKeyPair.getPrivate(), clientPublicKey,
                serverPublicKey, serverPublicKey, nonce);

        byte[] iv = randomBytes(IV_LENGTH);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] ciphertext = cipher.doFinal(token == null ? new byte[0] : token.getBytes(java.nio.charset.StandardCharsets.UTF_8));

        return new EncryptedToken(clientPublicKey, iv, ciphertext, key);
    }

    /**
     * Encrypt a later message (e.g. the token obtained through /log) with a key that was
     * established during the configuration handshake.
     */
    public static EncryptedMessage encryptWithKey(SecretKey key, String plaintext) throws GeneralSecurityException {
        byte[] iv = randomBytes(IV_LENGTH);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] ciphertext = cipher.doFinal(plaintext == null
                ? new byte[0]
                : plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return new EncryptedMessage(iv, ciphertext);
    }

    /**
     * @return decrypted text or {@code null} when the message was tampered with
     */
    @Nullable
    public static String decryptWithKey(SecretKey key, byte[] iv, byte[] ciphertext) {
        if (key == null || iv == null || iv.length != IV_LENGTH || ciphertext == null) {
            return null;
        }
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            return new String(cipher.doFinal(ciphertext), java.nio.charset.StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | RuntimeException e) {
            return null;
        }
    }

    /**
     * Server side: decrypt the token sent by the client.
     *
     * @return the token and the derived session key, or {@code null} when the payload was
     *         tampered with or does not match the pending handshake
     */
    @Nullable
    public static DecryptedToken decryptFromClient(PendingHandshake handshake, byte[] clientPublicKey, byte[] iv, byte[] ciphertext) {
        if (clientPublicKey == null || clientPublicKey.length == 0
                || iv == null || iv.length != IV_LENGTH
                || ciphertext == null) {
            return null;
        }

        try {
            byte[] serverPublicKey = encodedPublicKey(handshake.keyPair());
            SecretKey key = deriveKey(
                    handshake.keyPair().getPrivate(), serverPublicKey,
                    clientPublicKey, serverPublicKey, handshake.nonce());

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            byte[] plaintext = cipher.doFinal(ciphertext);
            return new DecryptedToken(new String(plaintext, java.nio.charset.StandardCharsets.UTF_8), key);
        } catch (GeneralSecurityException | RuntimeException e) {
            return null;
        }
    }

    /**
     * Both sides derive the same AES key. The HKDF salt is deterministic: it hashes the two
     * public keys in a fixed (sorted) order together with the server nonce.
     */
    private static SecretKey deriveKey(PrivateKey ownPrivate, byte[] ownPublic, byte[] peerPublic, byte[] serverPublic, byte[] nonce)
            throws GeneralSecurityException {
        KeyAgreement agreement = KeyAgreement.getInstance("X25519");
        agreement.init(ownPrivate);
        agreement.doPhase(parsePublicKey(peerPublic), true);
        byte[] sharedSecret = agreement.generateSecret();

        byte[] first = ownPublic;
        byte[] second = peerPublic;
        if (Arrays.compareUnsigned(first, second) > 0) {
            byte[] swap = first;
            first = second;
            second = swap;
        }

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        sha256.update(first);
        sha256.update(second);
        sha256.update(serverPublic);
        sha256.update(nonce);
        byte[] salt = sha256.digest();

        byte[] key = hkdfSha256(sharedSecret, salt, HKDF_INFO, AES_KEY_BITS / 8);
        return new SecretKeySpec(key, "AES");
    }

    private static PublicKey parsePublicKey(byte[] encoded) throws GeneralSecurityException {
        return KeyFactory.getInstance("X25519").generatePublic(new X509EncodedKeySpec(encoded));
    }

    private static KeyPair generateKeyPair() {
        try {
            return KeyPairGenerator.getInstance("X25519").generateKeyPair();
        } catch (GeneralSecurityException e) {
            // X25519 is part of every JDK 11+; this cannot happen on a supported runtime.
            throw new IllegalStateException("X25519 is not available", e);
        }
    }

    /**
     * Single-block HKDF-SHA256 (RFC 5869) вЂ” 32 bytes of output only.
     */
    private static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt.length == 0 ? new byte[32] : salt, "HmacSHA256"));
        byte[] prk = mac.doFinal(ikm);

        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        mac.update(info);
        mac.update((byte) 1);
        byte[] block = mac.doFinal();
        return Arrays.copyOf(block, length);
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }
}

