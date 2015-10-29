package com.github.davidmoten.security;

final class Preconditions {

    private Preconditions() {
        // prevent instantiation
    }

    static void checkNotNull(Object o, String message) {
        if (o == null)
            throw new NullPointerException(message);
    }

    static void checkNotNull(Object o) {
        checkNotNull(o, null);
    }

}
