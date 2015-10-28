package com.github.davidmoten.security;

import java.io.IOException;
import java.io.InputStream;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.io.ByteStreams;

public final class Classpath {

    private Classpath() {
        // prevent instantiation
    }

    public static byte[] bytesFrom(Class<?> cls, String resource) {
        return bytesFrom(cls.getResourceAsStream(resource));
    }

    @VisibleForTesting
    static byte[] bytesFrom(InputStream is) {
        Preconditions.checkNotNull(is, "InputStream cannot be null!");
        try {
            return ByteStreams.toByteArray(is);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
