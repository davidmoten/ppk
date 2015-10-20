package com.github.davidmoten.security;

import static com.github.davidmoten.security.PPK.decrypt;
import static com.github.davidmoten.security.PPK.encrypt;
import static com.github.davidmoten.security.PPK.readPrivateKey;
import static com.github.davidmoten.security.PPK.readPublicKey;
import static org.junit.Assert.assertEquals;

import java.io.UnsupportedEncodingException;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.Test;

public class PPKTest {

    @Test
    public void testEncryptAndDecrypt() throws UnsupportedEncodingException {
        PublicKey publicKey = readPublicKey(Classpath.bytesFrom("/public.der"));
        PrivateKey privateKey = readPrivateKey(Classpath.bytesFrom("/private.der"));
        String content = "Hello World";
        byte[] message = content.getBytes("UTF8");
        byte[] secret = encrypt(publicKey, message);
        byte[] recovered_message = decrypt(privateKey, secret);
        assertEquals(content, new String(recovered_message, "UTF8"));
    }
}
