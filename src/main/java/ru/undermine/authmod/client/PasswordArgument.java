package ru.undermine.authmod.client;

import java.util.Collection;
import java.util.List;

import com.mojang.brigadier.StringReader;
import com.mojang.brigadier.arguments.ArgumentType;
import com.mojang.brigadier.context.CommandContext;
import com.mojang.brigadier.exceptions.CommandSyntaxException;
import com.mojang.brigadier.exceptions.SimpleCommandExceptionType;

/**
 * A single password token for /reg. Unlike Brigadier's {@code string()} type it accepts
 * arbitrary non-whitespace characters (e.g. {@code !}, {@code @}, {@code $}), so common
 * passwords do not have to be quoted. Passwords with spaces can be used through the
 * in-game account screen instead.
 */
public final class PasswordArgument implements ArgumentType<String> {
    private static final SimpleCommandExceptionType EMPTY =
            new SimpleCommandExceptionType(() -> "A password is required");
    private static final PasswordArgument INSTANCE = new PasswordArgument();

    private PasswordArgument() {
    }

    public static PasswordArgument password() {
        return INSTANCE;
    }

    @Override
    public String parse(StringReader reader) throws CommandSyntaxException {
        int start = reader.getCursor();
        while (reader.canRead() && !Character.isWhitespace(reader.peek())) {
            reader.skip();
        }
        if (reader.getCursor() == start) {
            throw EMPTY.createWithContext(reader);
        }
        return reader.getString().substring(start, reader.getCursor());
    }

    @Override
    public Collection<String> getExamples() {
        return List.of("password", "hunter2");
    }

    public static String getPassword(CommandContext<?> context, String name) {
        return context.getArgument(name, String.class);
    }
}
