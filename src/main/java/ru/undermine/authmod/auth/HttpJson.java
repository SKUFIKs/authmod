package ru.undermine.authmod.auth;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.annotation.Nullable;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Small shared JSON-over-HTTP helper. All methods are non-blocking: the request
 * runs on a daemon executor and the caller gets a {@link CompletableFuture}.
 */
public final class HttpJson {
    private static final ExecutorService EXECUTOR = Executors.newFixedThreadPool(2, running -> {
        Thread thread = new Thread(running, "AuthMod-Http");
        thread.setDaemon(true);
        return thread;
    });

    private static volatile HttpClient httpClient;

    private HttpJson() {
    }

    public record Response(int status, String body) {
        public boolean ok() {
            return status >= 200 && status < 300;
        }
    }

    public static CompletableFuture<Response> postAsync(String url, @Nullable String bearerToken, @Nullable String jsonBody, int timeoutSeconds) {
        HttpRequest request;
        try {
            request = buildRequest(url, bearerToken, jsonBody, timeoutSeconds);
        } catch (RuntimeException e) {
            return CompletableFuture.completedFuture(new Response(0, e.getMessage() == null ? "bad request" : e.getMessage()));
        }
        return CompletableFuture.supplyAsync(() -> send(request), EXECUTOR);
    }

    private static HttpRequest buildRequest(String url, @Nullable String bearerToken, @Nullable String jsonBody, int timeoutSeconds) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(Math.max(1, timeoutSeconds)))
                .header("Accept", "application/json");
        if (bearerToken != null) {
            builder.header("Authorization", "Bearer " + bearerToken);
        }
        if (jsonBody == null) {
            builder.POST(HttpRequest.BodyPublishers.noBody());
        } else {
            builder.header("Content-Type", "application/json; charset=utf-8");
            builder.POST(HttpRequest.BodyPublishers.ofString(jsonBody, StandardCharsets.UTF_8));
        }
        return builder.build();
    }

    private static Response send(HttpRequest request) {
        try {
            HttpResponse<String> response = client()
                    .send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return new Response(response.statusCode(), response.body());
        } catch (IOException e) {
            return new Response(0, e.getClass().getSimpleName() + ": " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new Response(0, "interrupted");
        }
    }

    private static HttpClient client() {
        HttpClient client = httpClient;
        if (client == null) {
            synchronized (HttpJson.class) {
                if (httpClient == null) {
                    httpClient = HttpClient.newBuilder()
                            .connectTimeout(Duration.ofSeconds(10))
                            .followRedirects(HttpClient.Redirect.NORMAL)
                            .build();
                }
                client = httpClient;
            }
        }
        return client;
    }

    /**
     * @return parsed object or {@code null} when the body is not a JSON object
     */
    @Nullable
    public static JsonObject parseObject(@Nullable String body) {
        if (body == null || body.isBlank()) {
            return null;
        }
        try {
            return JsonParser.parseString(body).getAsJsonObject();
        } catch (RuntimeException e) {
            return null;
        }
    }
}
