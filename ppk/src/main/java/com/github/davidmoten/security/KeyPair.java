package com.github.davidmoten.security;

public final class KeyPair {

    private final byte[] privateKeyDer;
    private final byte[] publicKeyDer;

    public KeyPair(byte[] privateKeyDer, byte[] publicKeyDer) {
        this.privateKeyDer = privateKeyDer;
        this.publicKeyDer = publicKeyDer;
    }

    public byte[] privateKeyDer() {
        return privateKeyDer;
    }

    public byte[] publicKeyDer() {
        return publicKeyDer;
    }

}
