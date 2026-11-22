package ru.undermine.authmod.auth;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ApiEndpointsTest {
    @Test
    void joinsBaseUrlAndPath() {
        assertEquals("https://staging.undermine.click/api/v1.0/login",
                ApiEndpoints.join("https://staging.undermine.click/", "/api/v1.0/login"));
        assertEquals("https://staging.undermine.click/api/v1.0/login",
                ApiEndpoints.join("https://staging.undermine.click", "api/v1.0/login"));
    }

    @Test
    void defaultApiUrlUsesHttps() {
        assertTrue(ApiEndpoints.DEFAULT_BASE_URL.startsWith("https://"),
                "The default API URL must use HTTPS");
    }
}
