package com.github.davidmoten.security;

import java.io.IOException;

import com.google.common.io.ByteStreams;

public final class Classpath {

	public static byte[] bytesFrom(Class<?> cls, String resource) {
		try {
			return ByteStreams.toByteArray(cls.getResourceAsStream(resource));
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

}
