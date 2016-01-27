package com.github.davidmoten.security;

import java.io.InputStream;

public final class Classpath {

    private Classpath() {
        // prevent instantiation
    }

    public static byte[] bytesFrom(Class<?> cls, String resource) {
        return bytesFrom(cls.getResourceAsStream(resource));
    }

    // VisibleForTesting
    static byte[] bytesFrom(InputStream is) {
        Preconditions.checkNotNull(is, "InputStream cannot be null!");
        return Bytes.from(is);
    }

}
