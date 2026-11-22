package ru.undermine.authmod.auth;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthApiClientTest {
    @Test
    void parsesSuccessfulLogin() {
        AuthApiClient.AuthResponse response = AuthApiClient.parseLoginResponse(200, """
                {"token":"a.b.c","expiresIn":2592000,"success":true,"message":"","userId":3,"login":"authtest"}
                """);

        assertTrue(response.success());
        assertEquals("a.b.c", response.token());
        assertEquals(3L, response.userId());
        assertEquals("authtest", response.login());
    }

    @Test
    void parses401Failure() {
        AuthApiClient.AuthResponse response = AuthApiClient.parseLoginResponse(401, """
                {"status":401,"message":"Invalid username or password!"}
                """);

        assertFalse(response.success());
        assertEquals("Invalid username or password!", response.message());
    }

    @Test
    void parsesRegistrationErrors() {
        AuthApiClient.AuthResponse taken = AuthApiClient.parseLoginResponse(409, """
                {"status":409,"error":"USERNAME_TAKEN","message":"User with this username already exists!"}
                """);

        assertFalse(taken.success());
        assertEquals("USERNAME_TAKEN", taken.errorCode());
        assertEquals("User with this username already exists!", taken.message());

        AuthApiClient.AuthResponse limited = AuthApiClient.parseLoginResponse(429, """
                {"status":429,"error":"DEVICE_LIMIT","message":"Account limit exceeded for this device (2)."}
                """);

        assertFalse(limited.success());
        assertEquals("DEVICE_LIMIT", limited.errorCode());
    }

    @Test
    void rejectsLoginWithoutToken() {
        AuthApiClient.AuthResponse response = AuthApiClient.parseLoginResponse(200, """
                {"success":true,"message":"Registration successful!","userId":3,"login":"authtest"}
                """);

        assertFalse(response.success());
    }

    @Test
    void handlesNetworkFailure() {
        AuthApiClient.AuthResponse response = AuthApiClient.parseLoginResponse(0, "ConnectException: timeout");

        assertFalse(response.success());
        assertEquals("ConnectException: timeout", response.message());
    }
}
