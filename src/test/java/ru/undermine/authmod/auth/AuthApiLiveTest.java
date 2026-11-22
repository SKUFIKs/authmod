package ru.undermine.authmod.auth;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Optional integration check against the real API. Disabled unless the environment
 * provides credentials:
 *
 * <pre>
 * AUTHMOD_LIVE_LOGIN=authtest AUTHMOD_LIVE_PASSWORD=secret ./gradlew test --tests '*Live*'
 * </pre>
 */
@EnabledIfEnvironmentVariable(named = "AUTHMOD_LIVE_LOGIN", matches = ".+")
class AuthApiLiveTest {
    private static final String BASE_URL = System.getenv().getOrDefault("AUTHMOD_LIVE_API", "https://staging.undermine.click");

    @Test
    void logsInAndValidatesTheToken() {
        String login = System.getenv("AUTHMOD_LIVE_LOGIN");
        String password = System.getenv("AUTHMOD_LIVE_PASSWORD");

        AuthApiClient.AuthResponse response = AuthApiClient
                .loginAsync(BASE_URL, "/api/v1.0/login", 20, login, password)
                .join();

        assertTrue(response.success(), "login failed: " + response.message());
        assertTrue(response.token().contains("."), "the API returned no JWT");

        TokenValidator.Result validation = TokenValidator
                .validateAsync(BASE_URL, "/api/v1.0/validate-token", 20, response.token())
                .join();

        assertTrue(validation.valid(), "token validation failed: " + validation.message());

        TokenInfo info = JwtDecoder.decode(response.token(), "live test");
        assertTrue(info.name() != null && !info.name().isBlank());
        assertTrue(info.hasExpiry());
    }
}
