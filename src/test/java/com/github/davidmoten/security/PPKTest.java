package com.github.davidmoten.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.junit.Test;

import com.google.common.base.Charsets;
import com.google.common.collect.Lists;

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
    public void testEncryptAndDecryptWithDifferentPPKInstances()
            throws UnsupportedEncodingException {
        PPK ppk = PPK.publicKey("/public.der").build();
        PPK ppk2 = PPK.privateKey("/private.der").build();
        byte[] encrypted = ppk.encrypt(content, Charsets.UTF_8);
        String decrypted = ppk2.decrypt(encrypted, Charsets.UTF_8);
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
        byte[] bytes = PPK.publicKey("/public.der").encrypt(content, Charsets.UTF_8);
        assertEquals(content, PPK.privateKey("/private.der").decrypt(bytes, Charsets.UTF_8));
    }

    @Test
    public void testBuilderUsingFiles() {
        byte[] bytes = PPK.publicKey(new File("src/test/resources/public.der")).encrypt(content,
                Charsets.UTF_8);
        assertEquals(content, PPK.privateKey(new File("src/test/resources/private.der"))
                .decrypt(bytes, Charsets.UTF_8));
    }

    @Test
    public void testBuilderUsingInputStream() {
        byte[] bytes = PPK.publicKey(new File("src/test/resources/public.der"))
                .encrypt(new ByteArrayInputStream(content.getBytes(Charsets.UTF_8)));
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

    @Test
    public void testWithStream() {
        List<byte[]> list = Lists.newArrayList("hi".getBytes(), "there".getBytes());
        PPK ppk = PPK.publicKey("/public.der").build();
        List<byte[]> encrypted = list.stream().map(ppk::encrypt).collect(Collectors.toList());
        assertEquals(list.size(), encrypted.size());
    }

    @Test(expected = PublicKeyNotSetException.class)
    public void testPublicKeyNotSetThrowsException() {
        PPK.privateKey("/private.der").encrypt(content, Charsets.UTF_8);
    }

    @Test(expected = PrivateKeyNotSetException.class)
    public void testPrivateKeyNotSetThrowsException() {
        PPK.publicKey("/public.der").decrypt(content.getBytes(), Charsets.UTF_8);
    }

    @Test
    public void testRoundTrip() {
        PPK ppk = PPK.publicKey("/public.der").privateKey("/private.der").build();
        // result should be the same as bytes
        byte[] result = ppk.decrypt(ppk.encrypt(content.getBytes()));
        assertTrue(equal(content.getBytes(), result));
    }

    @Test
    public void testRoundTripZeroLength() {
        PPK ppk = PPK.publicKey("/public.der").privateKey("/private.der").build();
        // result should be the same as bytes
        byte[] result = ppk.decrypt(ppk.encrypt("".getBytes()));
        assertTrue(equal("".getBytes(), result));
    }

    @Test
    public void testLongRoundTrip() {
        String s = IntStream.range(0, 10000).mapToObj(x -> "a").collect(Collectors.joining());
        PPK ppk = PPK.publicKey("/public.der").privateKey("/private.der").build();
        byte[] enc = ppk.encrypt(s, Charsets.UTF_8);
        String s2 = ppk.decrypt(enc, Charsets.UTF_8);
        assertEquals(s, s2);
    }

    @Test
    public void testLongRoundTripUnique() {
        String s = IntStream.range(0, 10000).mapToObj(x -> "a").collect(Collectors.joining());
        PPK ppk = PPK.publicKey("/public.der").privateKey("/private.der").unique().build();
        byte[] enc = ppk.encrypt(s, Charsets.UTF_8);
        String s2 = ppk.decrypt(enc, Charsets.UTF_8);
        assertEquals(s, s2);
    }

    @Test
    public void testRoundTripHex() {
        PPK ppk = PPK.publicKey("/public.der").privateKey("/private.der").build();
        String hex = ppk.encryptAsHex(content, Charsets.UTF_8);
        String decoded = ppk.decryptHex(hex, Charsets.UTF_8);
        assertEquals(content, decoded);
    }

    @Test
    public void testRoundTripRSAHex() {
        PPK ppk = PPK.publicKey("/public.der").privateKey("/private.der").build();
        String hex = ppk.encryptRsaAsHex(content, Charsets.UTF_8);
        System.out.println(hex);
        String decoded = ppk.decryptRsaHex(hex, Charsets.UTF_8);
        System.out.println(decoded);
        assertEquals(content, decoded);
    }

    @Test
    public void testRoundTripPureRSA() {
        PPK ppk = PPK.publicKey("/public.der").privateKey("/private.der").build();
        String result = ppk.decryptRsa(ppk.encryptRsa(content, Charsets.UTF_8), Charsets.UTF_8);
        assertEquals(content, result);
    }

    @Test
    public void testRoundTripPureRSAInputMaxLength() {
        testRSA(214);
    }

    @Test(expected = InputTooLongException.class)
    public void testRoundTripPureRSAInputGreaterThanMaxLength() {
        testRSA(215);
    }

    @Test
    public void testRoundTripPureRSAZeroLength() {
        testRSA(0);
    }

    @Test(expected = NullPointerException.class)
    public void testNullPublicKeyFromResource() {
        PPK.publicKey((String) null);
    }

    @Test(expected = NullPointerException.class)
    public void testNullPublicKeyFromInputStream() {
        PPK.publicKey((InputStream) null);
    }

    @Test(expected = NullPointerException.class)
    public void testNullPublicKeyFromFile() {
        PPK.publicKey((File) null);
    }

    @Test(expected = NullPointerException.class)
    public void testNullPublicKeyFromByteArray() {
        PPK.publicKey((byte[]) null);
    }

    @Test(expected = NullPointerException.class)
    public void testNullPrivateKeyFromResource() {
        PPK.privateKey((String) null);
    }

    @Test(expected = NullPointerException.class)
    public void testNullPrivateKeyFromInputStream() {
        PPK.privateKey((InputStream) null);
    }

    @Test(expected = NullPointerException.class)
    public void testNullPrivateKeyFromFile() {
        PPK.privateKey((File) null);
    }

    @Test(expected = NullPointerException.class)
    public void testNullPrivateKeyFromByteArray() {
        PPK.privateKey((byte[]) null);
    }

    private void testRSA(int length) {
        PPK ppk = PPK.publicKey("/public.der").privateKey("/private.der").build();
        String content = IntStream.range(0, length).mapToObj(x -> "a")
                .collect(Collectors.joining());
        String result = ppk.decryptRsa(ppk.encryptRsa(content, Charsets.UTF_8), Charsets.UTF_8);
        assertEquals(content, result);
    }

    private static boolean equal(byte[] a, byte[] b) {
        if (a == null && b == null)
            return true;

        if (a == null || b == null)
            return false;

        if (a.length != b.length)
            return false;

        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i])
                return false;
        }
        return true;
    }

}
