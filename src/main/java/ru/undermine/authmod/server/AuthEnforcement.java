package ru.undermine.authmod.server;

import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import net.minecraft.ChatFormatting;
import net.minecraft.network.chat.ClickEvent;
import net.minecraft.network.chat.Component;
import net.minecraft.network.chat.MutableComponent;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.world.effect.MobEffectInstance;
import net.minecraft.world.effect.MobEffects;
import net.minecraft.world.entity.player.Player;
import net.minecraft.world.item.ItemStack;
import net.minecraft.world.phys.Vec3;

import net.neoforged.bus.api.ICancellableEvent;
import net.neoforged.bus.api.SubscribeEvent;
import net.neoforged.fml.common.EventBusSubscriber;
import net.neoforged.neoforge.common.util.TriState;
import net.neoforged.neoforge.event.CommandEvent;
import net.neoforged.neoforge.event.ServerChatEvent;
import net.neoforged.neoforge.event.entity.item.ItemTossEvent;
import net.neoforged.neoforge.event.entity.living.LivingIncomingDamageEvent;
import net.neoforged.neoforge.event.entity.player.AttackEntityEvent;
import net.neoforged.neoforge.event.entity.player.ItemEntityPickupEvent;
import net.neoforged.neoforge.event.entity.player.PlayerEvent;
import net.neoforged.neoforge.event.entity.player.PlayerInteractEvent;
import net.neoforged.neoforge.event.level.BlockEvent;
import net.neoforged.neoforge.event.server.ServerStoppedEvent;
import net.neoforged.neoforge.event.tick.PlayerTickEvent;

import ru.undermine.authmod.AuthMod;
import ru.undermine.authmod.auth.AuthServerConfig;
import ru.undermine.authmod.net.ServerAuth;

/**
 * Applies the "limbo" state to players who have not authenticated yet: frozen position,
 * blindness, blocked chat/commands and protected inventory (no pickup, toss, use, attack).
 * Players authenticate with /log or /reg; the client then sends the token over the
 * encrypted session channel.
 */
@EventBusSubscriber(modid = AuthMod.MODID)
public final class AuthEnforcement {
    private static final Set<UUID> READDING = ConcurrentHashMap.newKeySet();

    private AuthEnforcement() {
    }

    private static boolean restricted(Player player) {
        return player instanceof ServerPlayer serverPlayer
                && AuthServerConfig.ENABLED.get()
                && (serverPlayer.server.isDedicatedServer()
                    || AuthServerConfig.ENFORCE_ON_INTEGRATED_SERVER.get())
                && !AuthState.isAuthenticated(serverPlayer.getUUID());
    }

    @SubscribeEvent
    static void onLoggedIn(PlayerEvent.PlayerLoggedInEvent event) {
        if (event.getEntity() instanceof ServerPlayer player && restricted(player)) {
            enterLimbo(player);
            Component notice = AuthState.takeNotice(player.getUUID());
            if (notice != null) {
                player.sendSystemMessage(notice);
            }
            sendReminder(player);
        }
    }

    @SubscribeEvent
    static void onLoggedOut(PlayerEvent.PlayerLoggedOutEvent event) {
        if (event.getEntity() instanceof ServerPlayer player) {
            AuthState.clear(player.getUUID());
            ServerAuth.clearConnection(player.connection.getConnection());
        }
    }

    @SubscribeEvent
    static void onRespawn(PlayerEvent.PlayerRespawnEvent event) {
        if (event.getEntity() instanceof ServerPlayer player && restricted(player)) {
            AuthState.anchor(player);
            blind(player);
            sendReminder(player);
        }
    }

    @SubscribeEvent
    static void onChangedDimension(PlayerEvent.PlayerChangedDimensionEvent event) {
        if (event.getEntity() instanceof ServerPlayer player && restricted(player)) {
            AuthState.anchor(player);
            blind(player);
            sendReminder(player);
        }
    }

    @SubscribeEvent
    static void onServerStopped(ServerStoppedEvent event) {
        AuthState.clearAll();
        ServerAuth.clearAllSessions();
    }

    @SubscribeEvent
    static void onPlayerTick(PlayerTickEvent.Post event) {
        if (!(event.getEntity() instanceof ServerPlayer player) || !restricted(player)) {
            return;
        }

        freeze(player);

        if (player.tickCount % 20 == 0) {
            if (checkTimeout(player)) {
                return;
            }
            blind(player);
            sendCountdown(player);
        }

        if (AuthState.reminderDue(player.getUUID(), AuthServerConfig.REMINDER_SECONDS.get())) {
            sendReminder(player);
        }
    }

    @SubscribeEvent
    static void onChat(ServerChatEvent event) {
        if (restricted(event.getPlayer())) {
            event.setCanceled(true);
            sendBlocked(event.getPlayer());
        }
    }

    @SubscribeEvent
    static void onCommand(CommandEvent event) {
        if (event.getParseResults().getContext().getSource().getEntity() instanceof ServerPlayer player
                && restricted(player)) {
            event.setCanceled(true);
            sendBlocked(player);
        }
    }

    @SubscribeEvent
    static void onItemToss(ItemTossEvent event) {
        if (!restricted(event.getPlayer())) {
            return;
        }

        event.setCanceled(true);
        Player player = event.getPlayer();
        if (!READDING.add(player.getUUID())) {
            // Already restoring a stack: allow the overflow drop to avoid an infinite loop.
            return;
        }
        try {
            ItemStack stack = event.getEntity().getItem().copy();
            if (!player.getInventory().add(stack)) {
                player.getInventory().placeItemBackInInventory(stack);
            }
            if (player instanceof ServerPlayer serverPlayer) {
                serverPlayer.inventoryMenu.broadcastChanges();
            }
        } finally {
            READDING.remove(player.getUUID());
        }
        if (player instanceof ServerPlayer serverPlayer) {
            sendBlocked(serverPlayer);
        }
    }

    @SubscribeEvent
    static void onItemPickup(ItemEntityPickupEvent.Pre event) {
        if (restricted(event.getPlayer())) {
            event.setCanPickup(TriState.FALSE);
            if (event.getPlayer() instanceof ServerPlayer player) {
                sendBlocked(player);
            }
        }
    }

    @SubscribeEvent
    static void onRightClickBlock(PlayerInteractEvent.RightClickBlock event) {
        blockInteraction(event, event.getEntity());
    }

    @SubscribeEvent
    static void onRightClickItem(PlayerInteractEvent.RightClickItem event) {
        blockInteraction(event, event.getEntity());
    }

    @SubscribeEvent
    static void onEntityInteract(PlayerInteractEvent.EntityInteract event) {
        blockInteraction(event, event.getEntity());
    }

    @SubscribeEvent
    static void onEntityInteractSpecific(PlayerInteractEvent.EntityInteractSpecific event) {
        blockInteraction(event, event.getEntity());
    }

    @SubscribeEvent
    static void onLeftClickBlock(PlayerInteractEvent.LeftClickBlock event) {
        blockInteraction(event, event.getEntity());
    }

    private static void blockInteraction(ICancellableEvent event, Player player) {
        if (restricted(player)) {
            event.setCanceled(true);
            if (player instanceof ServerPlayer serverPlayer) {
                sendBlocked(serverPlayer);
            }
        }
    }

    @SubscribeEvent
    static void onAttack(AttackEntityEvent event) {
        if (restricted(event.getEntity())) {
            event.setCanceled(true);
            if (event.getEntity() instanceof ServerPlayer player) {
                sendBlocked(player);
            }
        }
    }

    @SubscribeEvent
    static void onBlockBreak(BlockEvent.BreakEvent event) {
        if (restricted(event.getPlayer())) {
            event.setCanceled(true);
            if (event.getPlayer() instanceof ServerPlayer player) {
                sendBlocked(player);
            }
        }
    }

    @SubscribeEvent
    static void onIncomingDamage(LivingIncomingDamageEvent event) {
        if (event.getEntity() instanceof ServerPlayer player && restricted(player)) {
            event.setCanceled(true);
        }
    }

    // --- helpers ------------------------------------------------------------

    private static void enterLimbo(ServerPlayer player) {
        AuthState.anchor(player);
        blind(player);
        player.setDeltaMovement(Vec3.ZERO);
        player.resetFallDistance();

        int timeoutSeconds = AuthServerConfig.AUTH_TIMEOUT_SECONDS.get();
        if (timeoutSeconds > 0) {
            AuthState.setDeadline(player.getUUID(), System.currentTimeMillis() + timeoutSeconds * 1000L);
        } else {
            AuthState.clearDeadline(player.getUUID());
        }
    }

    /**
     * @return true when the player was disconnected because the auth timer expired
     */
    private static boolean checkTimeout(ServerPlayer player) {
        int timeoutSeconds = AuthServerConfig.AUTH_TIMEOUT_SECONDS.get();
        if (timeoutSeconds <= 0) {
            return false;
        }

        long remaining = AuthState.remainingSeconds(player.getUUID());
        if (remaining != 0) {
            return false;
        }

        AuthMod.LOGGER.info("Player {} disconnected: authentication timeout ({} s)",
                player.getGameProfile().getName(), timeoutSeconds);
        AuthState.clear(player.getUUID());
        player.connection.disconnect(Component.translatable("message.authmod.auth_timeout", timeoutSeconds));
        return true;
    }

    private static void sendCountdown(ServerPlayer player) {
        int timeoutSeconds = AuthServerConfig.AUTH_TIMEOUT_SECONDS.get();
        if (timeoutSeconds <= 0) {
            return;
        }

        long remaining = AuthState.remainingSeconds(player.getUUID());
        if (remaining < 0) {
            return;
        }

        String key = AuthState.hasAccountHint(player.getUUID())
                ? "authmod.auth.countdown.login"
                : "authmod.auth.countdown.register";
        ChatFormatting color = remaining <= 10 ? ChatFormatting.RED : ChatFormatting.YELLOW;
        player.displayClientMessage(Component.translatable(key, remaining).withStyle(color), true);
    }

    private static void freeze(ServerPlayer player) {
        Vec3 anchor = AuthState.anchor(player.getUUID());
        if (anchor == null) {
            AuthState.anchor(player);
            anchor = player.position();
        }

        player.setDeltaMovement(Vec3.ZERO);
        player.resetFallDistance();

        if (player.position().distanceToSqr(anchor) > 0.01D) {
            player.connection.teleport(anchor.x, anchor.y, anchor.z, player.getYRot(), player.getXRot());
        }
    }

    private static void blind(ServerPlayer player) {
        player.addEffect(new MobEffectInstance(MobEffects.BLINDNESS, 80, 0, false, false, false));
    }

    public static void clearBlindness(ServerPlayer player) {
        player.removeEffect(MobEffects.BLINDNESS);
    }

    private static void sendReminder(ServerPlayer player) {
        boolean known = AuthState.hasAccountHint(player.getUUID());
        String chatKey = known ? "authmod.auth.reminder.chat.login" : "authmod.auth.reminder.chat.register";
        String barKey = known ? "authmod.auth.reminder.actionbar.login" : "authmod.auth.reminder.actionbar.register";
        String suggestion = known ? "/log " : "/reg ";

        long remaining = AuthState.remainingSeconds(player.getUUID());
        int timeoutSeconds = AuthServerConfig.AUTH_TIMEOUT_SECONDS.get();

        MutableComponent chat = Component.translatable(chatKey);
        if (timeoutSeconds > 0 && remaining >= 0) {
            chat.append(Component.literal(" "))
                    .append(Component.translatable("authmod.auth.reminder.time", remaining));
        }

        ChatFormatting color = timeoutSeconds > 0 && remaining >= 0 && remaining <= 10
                ? ChatFormatting.RED
                : ChatFormatting.YELLOW;
        chat.withStyle(color)
                .withStyle(style -> style.withClickEvent(new ClickEvent(ClickEvent.Action.SUGGEST_COMMAND, suggestion)));

        player.sendSystemMessage(chat);
        player.displayClientMessage(Component.translatable(barKey).withStyle(color), true);
    }

    private static void sendBlocked(ServerPlayer player) {
        if (AuthState.blockedNoticeDue(player.getUUID())) {
            player.displayClientMessage(Component.translatable("authmod.auth.blocked")
                    .withStyle(ChatFormatting.RED), true);
        }
    }
}
