package ru.undermine.authmod.auth;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtDecoderTest {
    private static final String NAME_URI = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";
    private static final String ROLE_URI = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role";

    @Test
    void decodesShortClaims() {
        String token = token("""
                {"sub":"42","UserId":"42","unique_name":"Steve","role":"admin","exp":9999999999}
                """);

        TokenInfo info = JwtDecoder.decode(token, "test");

        assertEquals("Steve", info.name());
        assertEquals("42", info.userId());
        assertEquals("admin", info.role());
        assertEquals(9999999999L, info.expiresAtEpochSeconds());
        assertTrue(info.hasExpiry());
    }

    @Test
    void decodesMicrosoftClaimUrisUsedByTheApi() {
        String token = token("""
                {"sub":"3","UserId":"3",
                 "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name":"authtest885243",
                 "http://schemas.microsoft.com/ws/2008/06/identity/claims/role":"user",
                 "token_version":"0","exp":1797936261}
                """);

        TokenInfo info = JwtDecoder.decode(token, "test");

        assertEquals("authtest885243", info.name());
        assertEquals("3", info.userId());
        assertEquals("user", info.role());
        assertEquals(1797936261L, info.expiresAtEpochSeconds());
    }

    @Test
    void acceptsUnpaddedBase64UrlPayload() {
        // The API's tokens are signed JWTs; only the payload is needed here.
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString("""
                {"sub":"7","unique_name":"Alex","exp":1900000000}
                """.getBytes(StandardCharsets.UTF_8));
        TokenInfo info = JwtDecoder.decode("header." + payload + ".signature", "test");

        assertEquals("Alex", info.name());
        assertEquals("7", info.userId());
    }

    @Test
    void rejectsNonJwtInput() {
        assertThrows(IllegalArgumentException.class, () -> JwtDecoder.decode("not-a-token", "test"));
        assertThrows(IllegalArgumentException.class, () -> JwtDecoder.decode("", "test"));
    }

    private static String token(String payloadJson) {
        String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + ".signature";
    }
}
