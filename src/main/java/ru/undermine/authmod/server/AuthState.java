package ru.undermine.authmod.server;

import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import javax.annotation.Nullable;

import net.minecraft.network.chat.Component;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.world.phys.Vec3;

/**
 * Server-side authentication state: who is authenticated, where an unauthenticated
 * player is anchored (to freeze movement), pending notices and reminder timers.
 */
public final class AuthState {
    private static final Set<UUID> AUTHENTICATED = ConcurrentHashMap.newKeySet();
    private static final Map<UUID, Vec3> ANCHORS = new ConcurrentHashMap<>();
    private static final Map<UUID, Component> NOTICES = new ConcurrentHashMap<>();
    private static final Map<UUID, Long> LAST_REMINDER = new ConcurrentHashMap<>();
    private static final Map<UUID, Long> LAST_BLOCKED = new ConcurrentHashMap<>();
    private static final Map<UUID, Long> LAST_ATTEMPT = new ConcurrentHashMap<>();
    private static final Map<UUID, Boolean> ACCOUNT_HINTS = new ConcurrentHashMap<>();
    private static final Map<UUID, Long> DEADLINES = new ConcurrentHashMap<>();

    private AuthState() {
    }

    public static boolean isAuthenticated(UUID playerId) {
        return AUTHENTICATED.contains(playerId);
    }

    public static void markAuthenticated(UUID playerId) {
        AUTHENTICATED.add(playerId);
        ANCHORS.remove(playerId);
        NOTICES.remove(playerId);
        LAST_REMINDER.remove(playerId);
        LAST_BLOCKED.remove(playerId);
        LAST_ATTEMPT.remove(playerId);
        DEADLINES.remove(playerId);
    }

    /**
     * Client-provided hint: true when the client already used this account successfully,
     * so the prompt can say /log instead of /reg. Not authoritative (the API does not
     * expose account existence).
     */
    public static void setAccountHint(UUID playerId, boolean knownAccount) {
        ACCOUNT_HINTS.put(playerId, knownAccount);
    }

    public static boolean hasAccountHint(@Nullable UUID playerId) {
        return playerId != null && ACCOUNT_HINTS.getOrDefault(playerId, false);
    }

    public static void markUnauthenticated(UUID playerId, @Nullable Component notice) {
        AUTHENTICATED.remove(playerId);
        if (notice != null) {
            NOTICES.put(playerId, notice);
        }
    }

    @Nullable
    public static Component takeNotice(UUID playerId) {
        return NOTICES.remove(playerId);
    }

    public static void anchor(ServerPlayer player) {
        ANCHORS.put(player.getUUID(), player.position());
    }

    /**
     * Starts (or restarts) the authentication countdown for a player.
     */
    public static void setDeadline(UUID playerId, long deadlineEpochMillis) {
        DEADLINES.put(playerId, deadlineEpochMillis);
    }

    /**
     * @return seconds left, 0 when the deadline has passed, or -1 when no timer is running
     */
    public static long remainingSeconds(UUID playerId) {
        Long deadline = DEADLINES.get(playerId);
        if (deadline == null) {
            return -1L;
        }
        long remainingMillis = deadline - System.currentTimeMillis();
        if (remainingMillis <= 0) {
            return 0L;
        }
        return (remainingMillis + 999L) / 1000L;
    }

    public static void clearDeadline(UUID playerId) {
        DEADLINES.remove(playerId);
    }

    @Nullable
    public static Vec3 anchor(UUID playerId) {
        return ANCHORS.get(playerId);
    }

    /**
     * @return true when the periodic chat reminder should be shown now
     */
    public static boolean reminderDue(UUID playerId, int intervalSeconds) {
        return due(LAST_REMINDER, playerId, Math.max(1, intervalSeconds) * 1000L);
    }

    /**
     * @return true when the "you must authenticate first" action-bar hint should be shown
     */
    public static boolean blockedNoticeDue(UUID playerId) {
        return due(LAST_BLOCKED, playerId, 2500L);
    }

    /**
     * @return true when another authentication attempt may be sent to the API
     */
    public static boolean attemptDue(UUID playerId, int cooldownSeconds) {
        return due(LAST_ATTEMPT, playerId, Math.max(0, cooldownSeconds) * 1000L);
    }

    private static boolean due(Map<UUID, Long> map, UUID playerId, long intervalMillis) {
        long now = System.currentTimeMillis();
        Long last = map.get(playerId);
        if (last != null && now - last < intervalMillis) {
            return false;
        }
        map.put(playerId, now);
        return true;
    }

    public static void clear(UUID playerId) {
        AUTHENTICATED.remove(playerId);
        ANCHORS.remove(playerId);
        NOTICES.remove(playerId);
        LAST_REMINDER.remove(playerId);
        LAST_BLOCKED.remove(playerId);
        LAST_ATTEMPT.remove(playerId);
        ACCOUNT_HINTS.remove(playerId);
        DEADLINES.remove(playerId);
    }

    public static void clearAll() {
        AUTHENTICATED.clear();
        ANCHORS.clear();
        NOTICES.clear();
        LAST_REMINDER.clear();
        LAST_BLOCKED.clear();
        LAST_ATTEMPT.clear();
        ACCOUNT_HINTS.clear();
        DEADLINES.clear();
    }
}
