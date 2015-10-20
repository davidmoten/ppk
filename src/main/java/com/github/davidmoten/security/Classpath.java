package com.github.davidmoten.security;

import java.io.IOException;

import com.google.common.io.ByteStreams;

public final class Classpath {

    public static byte[] bytesFrom(String resource) {
        try {
            return ByteStreams.toByteArray(Classpath.class.getResourceAsStream(resource));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
