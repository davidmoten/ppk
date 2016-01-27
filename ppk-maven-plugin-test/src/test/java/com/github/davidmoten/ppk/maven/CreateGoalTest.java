package com.github.davidmoten.ppk.maven;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.nio.charset.StandardCharsets;

import org.junit.Test;

import com.github.davidmoten.security.PPK;

public class CreateGoalTest {

    @Test
    public void test() {
        byte[] bytes = PPK.publicKey(new File("target/public.der")).encrypt("Hello",
                StandardCharsets.UTF_8);
        assertEquals("Hello", PPK.privateKey(new File("target/private.der")).decrypt(bytes,
                StandardCharsets.UTF_8));
    }

}
