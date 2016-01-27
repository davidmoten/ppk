package com.github.davidmoten.ppk.maven;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;

import org.junit.Test;

public class DecryptGoalTest {

    @Test
    public void test() throws IOException {
        String text = new String(Files.readAllBytes(new File("target/temp.txt").toPath()),
                Charset.forName("UTF-8"));
        assertEquals("Hello World", text);
    }

}
