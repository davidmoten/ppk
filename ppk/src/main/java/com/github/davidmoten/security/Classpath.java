package com.github.davidmoten.security;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;

public final class Classpath {

    private Classpath() {
        // prevent instantiation
    }

    public static byte[] bytesFrom(Class<?> cls, String resource) {
        try (InputStream in = cls.getResourceAsStream(resource)) {
            return bytesFrom(in);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    // VisibleForTesting
    static byte[] bytesFrom(InputStream is) {
        Preconditions.checkNotNull(is, "InputStream cannot be null!");
        return Bytes.from(is);
    }

}
