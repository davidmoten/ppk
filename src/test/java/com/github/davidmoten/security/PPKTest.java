package com.github.davidmoten.security;

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.UnsupportedEncodingException;

import org.junit.Test;

import com.google.common.base.Charsets;

public class PPKTest {
    private static final String content = "Hello World";

    @Test
    public void testEncryptAndDecrypt() throws UnsupportedEncodingException {
        PPK ppk = PPK.publicKey("/public.der").privateKey("/private.der").build();
        byte[] encrypted = ppk.encrypt(content, Charsets.UTF_8);
        String decrypted = ppk.decrypt(encrypted, Charsets.UTF_8);
        assertEquals(content, decrypted);
    }

    @Test
    public void testEncryptAndDecryptSwitchOrder() throws UnsupportedEncodingException {
        PPK ppk = PPK.privateKey("/private.der").publicKey("/public.der").build();
        byte[] encrypted = ppk.encrypt(content, Charsets.UTF_8);
        String decrypted = ppk.decrypt(encrypted, Charsets.UTF_8);
        assertEquals(content, decrypted);
    }

    @Test
    public void testBuilder() {
        byte[] bytes = PPK.publicKey("/public.der").encrypt("Hello World", Charsets.UTF_8);
        assertEquals(content, PPK.privateKey("/private.der").decrypt(bytes, Charsets.UTF_8));
    }

    @Test
    public void testBuilderUsingFiles() {
        byte[] bytes = PPK.publicKey(new File("src/test/resources/public.der"))
                .encrypt("Hello World", Charsets.UTF_8);
        assertEquals(content, PPK.privateKey(new File("src/test/resources/private.der"))
                .decrypt(bytes, Charsets.UTF_8));
    }

    @Test
    public void testBuilderUsingInputStream() {
        byte[] bytes = PPK.publicKey(new File("src/test/resources/public.der"))
                .encrypt(new ByteArrayInputStream("Hello World".getBytes(Charsets.UTF_8)));
        assertEquals(content, PPK.privateKey(new File("src/test/resources/private.der"))
                .decrypt(bytes, Charsets.UTF_8));
    }

    @Test(expected = RuntimeException.class)
    public void testBuilderUsingPublicKeyFileThrowsExceptionWhenFileDoesNotExist() {
        PPK.publicKey(new File("src/test/resources/publicDoesNotExist.der"));
    }

    @Test(expected = RuntimeException.class)
    public void testBuilderUsingPrivateKeyFileThrowsExceptionWhenFileDoesNotExist() {
        PPK.privateKey(new File("src/test/resources/privateDoesNotExist.der"));
    }

}
