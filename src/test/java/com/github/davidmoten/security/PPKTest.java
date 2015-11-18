package com.github.davidmoten.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.junit.Test;

public class PPKTest {

    private static final String content = "Hello World";

    @Test
    public void testEncryptAndDecrypt() throws UnsupportedEncodingException {
        PPK ppk = PPK.publicKey("/public.der").privateKey("/private.der").build();
        byte[] encrypted = ppk.encrypt(content, StandardCharsets.UTF_8);
        String decrypted = ppk.decrypt(encrypted, StandardCharsets.UTF_8);
        assertEquals(content, decrypted);
    }

    @Test
    public void testEncryptAndDecryptWithDifferentPPKInstances()
            throws UnsupportedEncodingException {
        PPK ppk = PPK.publicKey("/public.der").build();
        PPK ppk2 = PPK.privateKey("/private.der").build();
        byte[] encrypted = ppk.encrypt(content, StandardCharsets.UTF_8);
        String decrypted = ppk2.decrypt(encrypted, StandardCharsets.UTF_8);
        assertEquals(content, decrypted);
    }

    @Test
    public void testEncryptAndDecryptSwitchOrder() throws UnsupportedEncodingException {
        PPK ppk = PPK.privateKey("/private.der").publicKey("/public.der").build();
        byte[] encrypted = ppk.encrypt(content, StandardCharsets.UTF_8);
        String decrypted = ppk.decrypt(encrypted, StandardCharsets.UTF_8);
        assertEquals(content, decrypted);
    }

    @Test
    public void testBuilder() {
        byte[] bytes = PPK.publicKey("/public.der").encrypt(content, StandardCharsets.UTF_8);
        assertEquals(content,
                PPK.privateKey("/private.der").decrypt(bytes, StandardCharsets.UTF_8));
    }

    @Test
    public void testBuilderUsingFiles() {
        byte[] bytes = PPK.publicKey(new File("src/test/resources/public.der")).encrypt(content,
                StandardCharsets.UTF_8);
        assertEquals(content, PPK.privateKey(new File("src/test/resources/private.der"))
                .decrypt(bytes, StandardCharsets.UTF_8));
    }

    @Test
    public void testBuilderUsingInputStream() {
        byte[] bytes = PPK.publicKey(new File("src/test/resources/public.der"))
                .encrypt(new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8)));
        assertEquals(content, PPK.privateKey(new File("src/test/resources/private.der"))
                .decrypt(bytes, StandardCharsets.UTF_8));
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
        List<byte[]> list = Arrays.asList("hi".getBytes(), "there".getBytes());
        PPK ppk = PPK.publicKey("/public.der").build();
        List<byte[]> encrypted = list.stream().map(ppk::encrypt).collect(Collectors.toList());
        assertEquals(list.size(), encrypted.size());
    }

    @Test(expected = PublicKeyNotSetException.class)
    public void testPublicKeyNotSetThrowsException() {
        PPK.privateKey("/private.der").encrypt(content, StandardCharsets.UTF_8);
    }

    @Test(expected = PrivateKeyNotSetException.class)
    public void testPrivateKeyNotSetThrowsException() {
        PPK.publicKey("/public.der").decrypt(content.getBytes(), StandardCharsets.UTF_8);
    }

    @Test
    public void testRoundTrip() {
        PPK ppk = PPK.publicKey("/public.der").privateKey("/private.der").build();
        // result should be the same as bytes
        byte[] result = ppk.decrypt(ppk.encrypt(content.getBytes()));
        assertTrue(Arrays.equals(content.getBytes(), result));
    }

    @Test
    public void testEncryptAsBase64() {
        String value = PPK.publicKey("/public.der").encryptAsBase64("mypassword");
        System.out.println(value);
    }

    @Test
    public void testRoundTripZeroLength() {
        PPK ppk = PPK.publicKey("/public.der").privateKey("/private.der").build();
        // result should be the same as bytes
        byte[] result = ppk.decrypt(ppk.encrypt("".getBytes()));
        assertTrue(Arrays.equals("".getBytes(), result));
    }

    @Test
    public void testLongRoundTrip() {
        String s = IntStream.range(0, 10000).mapToObj(x -> "a").collect(Collectors.joining());
        PPK ppk = PPK.publicKey("/public.der").privateKey("/private.der").build();
        byte[] enc = ppk.encrypt(s, StandardCharsets.UTF_8);
        String s2 = ppk.decrypt(enc, StandardCharsets.UTF_8);
        assertEquals(s, s2);
    }

    @Test
    public void testLongRoundTripUnique() {
        String s = IntStream.range(0, 10000).mapToObj(x -> "a").collect(Collectors.joining());
        PPK ppk = PPK.publicKey("/public.der").privateKey("/private.der").unique().build();
        byte[] enc = ppk.encrypt(s, StandardCharsets.UTF_8);
        String s2 = ppk.decrypt(enc, StandardCharsets.UTF_8);
        assertEquals(s, s2);
    }

    @Test
    public void testRoundTripUsingInputStreamsForKeys() {
        PPK ppk = PPK.publicKey(PPKTest.class.getResourceAsStream("/public.der"))
                .privateKey(PPKTest.class.getResourceAsStream("/private.der")).build();
        // result should be the same as bytes
        byte[] result = ppk.decrypt(ppk.encrypt(content.getBytes()));
        assertTrue(Arrays.equals(content.getBytes(), result));
    }

    @Test
    public void testRoundTripBase64() {
        PPK ppk = PPK.publicKey("/public.der").privateKey("/private.der").build();
        String b64 = ppk.encryptAsBase64(content);
        String decoded = ppk.decryptBase64(b64);
        assertEquals(content, decoded);
    }

    @Test
    public void testRoundTripRsaBase64() {
        PPK ppk = PPK.publicKey("/public.der").privateKey("/private.der").build();
        String b64 = ppk.encryptRsaAsBase64(content);
        String decoded = ppk.decryptRsaBase64(b64);
        assertEquals(content, decoded);
    }

    @Test
    public void testRoundTripPureRSA() {
        PPK ppk = PPK.publicKey("/public.der").privateKey("/private.der").build();
        String result = ppk.decryptRsa(ppk.encryptRsa(content, StandardCharsets.UTF_8),
                StandardCharsets.UTF_8);
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
        String result = ppk.decryptRsa(ppk.encryptRsa(content, StandardCharsets.UTF_8),
                StandardCharsets.UTF_8);
        assertEquals(content, result);
    }
}
