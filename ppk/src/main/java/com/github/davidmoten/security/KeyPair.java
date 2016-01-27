package com.github.davidmoten.security;

public final class KeyPair {

    private final byte[] privateKey;
    private final byte[] publicKey;

    public KeyPair(byte[] privateKey, byte[] publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public byte[] privateKey() {
        return privateKey;
    }

    public byte[] publicKey() {
        return publicKey;
    }

}
