package com.github.davidmoten.security;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.junit.Test;

import com.github.davidmoten.junit.Asserts;

public class ClasspathTest {

    @Test
    public void testFound() {
        byte[] bytes = Classpath.bytesFrom(ClasspathTest.class, "/test.txt");
        assertEquals("hello there", new String(bytes, StandardCharsets.UTF_8));
    }

    @Test(expected = NullPointerException.class)
    public void testNotFound() {
        Classpath.bytesFrom(ClasspathTest.class, "/testNotPresent.txt");
    }

    @Test(expected = RuntimeException.class)
    public void testIOExceptionFromInputStreamThrows() {
        Classpath.bytesFrom(new InputStream() {

            @Override
            public int read() throws IOException {
                throw new IOException("boo");
            }
        });
    }

    @Test
    public void testIsUtilityClass() {
        Asserts.assertIsUtilityClass(Classpath.class);
    }
}
