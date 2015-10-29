package com.github.davidmoten.security;

import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.Test;

import com.github.davidmoten.junit.Asserts;

public class BytesTest {

    @Test
    public void testIsUtilClass() {
        Asserts.assertIsUtilityClass(Bytes.class);
    }

    @Test(expected = NullPointerException.class)
    public void testNullInputStream() {
        Bytes.from(null);
    }

    @Test
    public void testRead() {
        assertTrue(Arrays.equals("hello there".getBytes(StandardCharsets.UTF_8),
                Bytes.from(BytesTest.class.getResourceAsStream("/test.txt"))));
    }

}
