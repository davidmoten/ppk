package com.github.davidmoten.security;

import static org.junit.Assert.assertEquals;

import org.junit.Assert;
import org.junit.Test;

import com.github.davidmoten.junit.Asserts;

public class PreconditionsTest {

    @Test
    public void testCheckNotNullDoesNotThrowIfInputNotNull() {
        Preconditions.checkNotNull(1);
    }

    @Test(expected = NullPointerException.class)
    public void testCheckNotNullDoesThrowIfInputNull() {
        Preconditions.checkNotNull(null);
    }

    @Test
    public void testCheckNotNullMessage() {
        try {
            Preconditions.checkNotNull(null, "boo");
            Assert.fail();
        } catch (NullPointerException e) {
            assertEquals("boo", e.getMessage());
        }
    }

    @Test
    public void testIsUtilClass() {
        Asserts.assertIsUtilityClass(Preconditions.class);
    }

}
