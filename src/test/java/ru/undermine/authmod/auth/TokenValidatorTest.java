package ru.undermine.authmod.auth;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TokenValidatorTest {
    @Test
    void parsesValidResponse() {
        TokenValidator.Result result = TokenValidator.parse(200, """
                {"valid":true,"message":"Token is valid"}
                """);

        assertEquals(TokenValidator.Outcome.VALID, result.outcome());
        assertTrue(result.valid());
    }

    @Test
    void parsesRejectedToken() {
        TokenValidator.Result result = TokenValidator.parse(401, """
                {"valid":false,"message":"Invalid or expired token"}
                """);

        assertEquals(TokenValidator.Outcome.INVALID, result.outcome());
        assertEquals("Invalid or expired token", result.message());
    }

    @Test
    void parsesRevokedTokenWithErrorCode() {
        TokenValidator.Result result = TokenValidator.parse(401, """
                {"status":401,"error":"TOKEN_REVOKED","message":"This session is no longer valid."}
                """);

        assertEquals(TokenValidator.Outcome.INVALID, result.outcome());
        assertEquals("TOKEN_REVOKED", result.errorCode());
    }

    @Test
    void parsesBannedAccount() {
        TokenValidator.Result result = TokenValidator.parse(403, """
                {"valid":false,"error":"ACCOUNT_BANNED","message":"This account is banned until 2027-01-01."}
                """);

        assertEquals(TokenValidator.Outcome.INVALID, result.outcome());
        assertEquals("ACCOUNT_BANNED", result.errorCode());
    }

    @Test
    void treatsServerErrorsAsErrors() {
        TokenValidator.Result result = TokenValidator.parse(500, "Internal Server Error");

        assertEquals(TokenValidator.Outcome.ERROR, result.outcome());
    }
}
