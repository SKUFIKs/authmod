package ru.undermine.authmod.client.gui;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import net.minecraft.ChatFormatting;
import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.EditBox;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.network.chat.Component;
import net.minecraft.network.chat.Style;
import net.minecraft.util.FormattedCharSequence;

import ru.undermine.authmod.AuthMod;
import ru.undermine.authmod.auth.ApiEndpoints;
import ru.undermine.authmod.auth.AuthApiClient;
import ru.undermine.authmod.auth.DeviceIdProvider;
import ru.undermine.authmod.auth.LauncherTokenProvider;
import ru.undermine.authmod.auth.SessionStore;
import ru.undermine.authmod.client.AccountHints;
import ru.undermine.authmod.net.ClientAuth;

/**
 * In-game UnderMine account screen: sign in or create an account without the launcher.
 * The token is stored in {@code config/authmod-session.json} and used for server auth.
 */
public class AuthScreen extends Screen {
    private static final int COLOR_TEXT = 0xFFFFFF;
    private static final int COLOR_MUTED = 0xA0A0A0;
    private static final int COLOR_ERROR = 0xFF5555;
    private static final int COLOR_SUCCESS = 0x55FF55;

    private final Screen parent;
    private EditBox loginBox;
    private EditBox passwordBox;
    private Button loginButton;
    private Button registerButton;
    private Button logoutButton;
    private Button closeButton;

    private Component status = Component.empty();
    private int statusColor = COLOR_MUTED;
    private boolean busy;

    public AuthScreen(Screen parent) {
        super(Component.translatable("authmod.auth.title"));
        this.parent = parent;
    }

    @Override
    protected void init() {
        int cx = this.width / 2;
        int top = this.height / 4;

        this.loginBox = new EditBox(this.font, cx - 100, top + 12, 200, 20,
                Component.translatable("authmod.auth.login_hint"));
        this.loginBox.setMaxLength(64);
        this.loginBox.setHint(Component.translatable("authmod.auth.login_hint"));
        addRenderableWidget(this.loginBox);

        this.passwordBox = new EditBox(this.font, cx - 100, top + 46, 200, 20,
                Component.translatable("authmod.auth.password_hint"));
        this.passwordBox.setMaxLength(72);
        this.passwordBox.setHint(Component.translatable("authmod.auth.password_hint"));
        this.passwordBox.setFormatter((value, cursor) ->
                FormattedCharSequence.forward("*".repeat(value.length()), Style.EMPTY));
        addRenderableWidget(this.passwordBox);

        this.loginButton = addRenderableWidget(Button.builder(
                        Component.translatable("authmod.auth.sign_in"), button -> signIn())
                .bounds(cx - 100, top + 84, 98, 20)
                .build());

        this.registerButton = addRenderableWidget(Button.builder(
                        Component.translatable("authmod.auth.register"), button -> register())
                .bounds(cx + 2, top + 84, 98, 20)
                .build());

        this.logoutButton = addRenderableWidget(Button.builder(
                        Component.translatable("authmod.auth.sign_out"), button -> signOut())
                .bounds(cx - 100, top + 110, 98, 20)
                .build());

        this.closeButton = addRenderableWidget(Button.builder(
                        Component.translatable("authmod.auth.close"), button -> onClose())
                .bounds(cx + 2, top + 110, 98, 20)
                .build());

        this.status = Component.empty();
        this.statusColor = COLOR_MUTED;
        refreshStatus();
    }

    private void refreshStatus() {
        if (this.busy || this.logoutButton == null) {
            return;
        }
        SessionStore.Session session = SessionStore.load().orElse(null);
        if (session != null) {
            setStatus(Component.translatable("authmod.auth.signed_in", session.login()), COLOR_SUCCESS);
        } else if (LauncherTokenProvider.find().isPresent()) {
            setStatus(Component.translatable("authmod.auth.launcher_session"), COLOR_MUTED);
        } else {
            setStatus(Component.translatable("authmod.auth.not_signed_in"), COLOR_MUTED);
        }
        this.logoutButton.active = session != null;
    }

    private void setStatus(Component message, int color) {
        this.status = message;
        this.statusColor = color;
    }

    private void setBusy(boolean busy) {
        this.busy = busy;
        if (this.loginButton != null) {
            this.loginButton.active = !busy;
            this.registerButton.active = !busy;
            this.logoutButton.active = !busy && SessionStore.hasSession();
            this.closeButton.active = !busy;
        }
        if (busy) {
            setStatus(Component.translatable("authmod.auth.working"), COLOR_MUTED);
        }
    }

    private void signIn() {
        if (this.busy) {
            return;
        }

        String login = this.loginBox.getValue().trim();
        String password = this.passwordBox.getValue();
        if (login.isEmpty() || password.isEmpty()) {
            setStatus(Component.translatable("authmod.auth.fill_fields"), COLOR_ERROR);
            return;
        }

        setBusy(true);
        Minecraft minecraft = Minecraft.getInstance();
        AuthApiClient.loginAsync(login, password).whenComplete((response, error) ->
                minecraft.execute(() -> finishAuth(response, error, false)));
    }

    private void register() {
        if (this.busy) {
            return;
        }

        String login = this.loginBox.getValue().trim();
        String password = this.passwordBox.getValue();
        if (login.isEmpty() || password.isEmpty()) {
            setStatus(Component.translatable("authmod.auth.fill_fields"), COLOR_ERROR);
            return;
        }

        int passwordBytes = password.getBytes(StandardCharsets.UTF_8).length;
        if (password.length() < 8 || passwordBytes > 72) {
            setStatus(Component.translatable("authmod.auth.password_policy"), COLOR_ERROR);
            return;
        }

        setBusy(true);
        Minecraft minecraft = Minecraft.getInstance();
        AuthApiClient.registerAsync(login, password, DeviceIdProvider.get()).whenComplete((response, error) ->
                minecraft.execute(() -> finishAuth(response, error, true)));
    }

    private void finishAuth(AuthApiClient.AuthResponse response, Throwable error, boolean registration) {
        if (this.minecraft == null || this.minecraft.screen != this) {
            return;
        }
        setBusy(false);

        if (error != null) {
            AuthMod.LOGGER.warn("In-game authentication failed", error);
            setStatus(Component.translatable("authmod.auth.request_failed",
                    String.valueOf(error.getMessage())), COLOR_ERROR);
            return;
        }
        if (response == null || !response.success()) {
            String message = response == null ? "unknown error" : response.message();
            setStatus(Component.literal(message == null || message.isBlank() ? "Authentication failed" : message), COLOR_ERROR);
            return;
        }

        try {
            SessionStore.save(response.token(), response.login(), response.userId());
        } catch (IOException e) {
            AuthMod.LOGGER.warn("Could not save the in-game session", e);
            setStatus(Component.translatable("authmod.auth.save_failed", String.valueOf(e.getMessage())), COLOR_ERROR);
            return;
        }

        this.passwordBox.setValue("");
        ClientAuth.sendSessionToken(response.token());
        AccountHints.remember(response.login() == null || response.login().isBlank()
                ? this.loginBox.getValue().trim()
                : response.login());
        String name = response.login() == null || response.login().isBlank()
                ? this.loginBox.getValue().trim()
                : response.login();
        setStatus(Component.translatable(
                registration ? "authmod.auth.registered" : "authmod.auth.logged_in", name), COLOR_SUCCESS);

        if (this.minecraft.player != null) {
            this.minecraft.player.displayClientMessage(
                    Component.translatable("authmod.auth.chat_logged_in", name).withStyle(ChatFormatting.GREEN),
                    false);
        }

        if (this.logoutButton != null) {
            this.logoutButton.active = true;
        }
    }

    private void signOut() {
        if (this.busy) {
            return;
        }
        SessionStore.clear();
        if (LauncherTokenProvider.find().isPresent()) {
            setStatus(Component.translatable("authmod.auth.signed_out_external"), COLOR_MUTED);
        } else {
            setStatus(Component.translatable("authmod.auth.signed_out"), COLOR_MUTED);
        }
        if (this.logoutButton != null) {
            this.logoutButton.active = false;
        }
    }

    @Override
    public void render(GuiGraphics graphics, int mouseX, int mouseY, float partialTick) {
        super.render(graphics, mouseX, mouseY, partialTick);

        int cx = this.width / 2;
        int top = this.height / 4;

        graphics.drawCenteredString(this.font, this.title, cx, top - 30, COLOR_TEXT);
        graphics.drawString(this.font, Component.translatable("authmod.auth.login"), cx - 100, top, COLOR_MUTED, false);
        graphics.drawString(this.font, Component.translatable("authmod.auth.password"), cx - 100, top + 34, COLOR_MUTED, false);

        if (!this.status.getString().isEmpty()) {
            graphics.drawCenteredString(this.font, this.status, cx, top + 140, this.statusColor);
        }

        graphics.drawCenteredString(this.font, Component.literal(ApiEndpoints.baseUrl()), cx, this.height - 30, 0x707070);
        graphics.drawCenteredString(this.font, Component.translatable("authmod.auth.hint"), cx, this.height - 18, 0x707070);
    }

    @Override
    public void onClose() {
        Minecraft minecraft = this.minecraft;
        if (minecraft != null) {
            minecraft.setScreen(this.parent);
        }
    }
}
