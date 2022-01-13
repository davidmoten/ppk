package com.github.davidmoten.security;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

final class Bytes {

    private Bytes() {
        // prevent instantiation
    }

    static byte[] from(InputStream is) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            int nRead;
            byte[] buffer = new byte[1024];
            while ((nRead = is.read(buffer)) != -1) {
                bytes.write(buffer, 0, nRead);
            }
            return bytes.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        } 
    }

}
