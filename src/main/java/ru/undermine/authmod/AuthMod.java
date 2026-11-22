package ru.undermine.authmod;

import org.slf4j.Logger;

import com.mojang.logging.LogUtils;

import net.neoforged.bus.api.IEventBus;
import net.neoforged.fml.ModContainer;
import net.neoforged.fml.common.Mod;
import net.neoforged.fml.config.ModConfig;

import ru.undermine.authmod.auth.AuthConfig;
import ru.undermine.authmod.auth.AuthServerConfig;
import ru.undermine.authmod.net.AuthNetwork;

/**
 * Authentication for games launched by the UnderMine launcher.
 *
 * <p>The launcher obtains a bearer token (JWT) from the UnderMine API and passes it into
 * the game ({@code --accessToken}, {@code UNDERMINE_AUTH_TOKEN} or the launcher's own
 * argument). The mod:
 * <ul>
 *   <li>on the client, checks the token locally and (for servers without this mod)
 *       validates it against the API;</li>
 *   <li>on the server, asks the client for the token during the configuration phase,
 *       validates it against the API and only then lets the player into the world.</li>
 * </ul>
 */
@Mod(AuthMod.MODID)
public class AuthMod {
    public static final String MODID = "authmod";
    public static final Logger LOGGER = LogUtils.getLogger();

    public AuthMod(IEventBus modEventBus, ModContainer modContainer) {
        modContainer.registerConfig(ModConfig.Type.CLIENT, AuthConfig.SPEC);
        modContainer.registerConfig(ModConfig.Type.SERVER, AuthServerConfig.SPEC);

        modEventBus.addListener(AuthNetwork::registerPayloads);
        modEventBus.addListener(AuthNetwork::registerConfigurationTasks);
    }
}
