package com.github.davidmoten.security;

public final class InputTooLongException extends IllegalArgumentException {

    private static final long serialVersionUID = -6268604494805242633L;

    public InputTooLongException(String message) {
        super(message);
    }

}
