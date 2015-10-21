package com.github.davidmoten.security;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Optional;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.google.common.io.ByteStreams;

public final class PPK {

    /*
     * We load the public cipher and private cipher and we generate an AES
     * cipher. The AES cipher is more efficient for encryption and decryption of
     * data when the data can be longer than the RSA cipher key size. We use the
     * public key to encrypt the AES cipher and prepend the AES encrypted bytes
     * with the rsa encrypted AES secret key. Thus the consumer has to read the
     * first N bytes and decrypt the AES secret key using the rsa private key
     * and then can decrypt the remaining bytes in the message using the AES
     * secret key.
     */

    private static final String RSA = "RSA";
    private static final String AES = "AES";
    private static final int AES_KEY_BITS = 128;// multiple of 8
    private static final int AES_KEY_BYTES = AES_KEY_BITS / 8;
    private final Optional<Cipher> publicCipher;
    private final Optional<Cipher> privateCipher;
    private final SecretKeySpec aesKeySpec;
    private final Cipher aesCipher;
    private final byte[] aesKey;

    private PPK(Optional<Cipher> publicCipher, Optional<Cipher> privateCipher) {
        this.publicCipher = publicCipher;
        this.privateCipher = privateCipher;
        try {
            KeyGenerator kgen = KeyGenerator.getInstance(AES);
            kgen.init(AES_KEY_BITS);
            SecretKey key = kgen.generateKey();
            aesKey = key.getEncoded();
            aesKeySpec = new SecretKeySpec(aesKey, AES);
            aesCipher = Cipher.getInstance(AES);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    public static final Builder privateKey(Class<?> cls, String resource) {
        return new Builder().privateKey(cls, resource);
    }

    public static final Builder privateKey(String resource) {
        return new Builder().privateKey(resource);
    }

    public static final Builder privateKey(InputStream is) {
        return new Builder().privateKey(is);
    }

    public static final Builder privateKey(File file) {
        return new Builder().privateKey(file);
    }

    public static final Builder publicKey(Class<?> cls, String resource) {
        return new Builder().publicKey(cls, resource);
    }

    public static final Builder publicKey(String resource) {
        return new Builder().publicKey(resource);
    }

    public static final Builder publicKey(File file) {
        return new Builder().publicKey(file);
    }

    public static final Builder publicKey(InputStream is) {
        return new Builder().publicKey(is);
    }

    public static final class Builder {
        private Optional<Cipher> publicCipher = Optional.empty();
        private Optional<Cipher> privateCipher = Optional.empty();

        private Builder() {
            // prevent instantiation
        }

        public Builder publicKey(InputStream is) {
            try {
                return publicKey(ByteStreams.toByteArray(is));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        public Builder privateKey(InputStream is) {
            try {
                return privateKey(ByteStreams.toByteArray(is));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        public Builder publicKey(byte[] bytes) {
            publicCipher = Optional.of(readPublicCipher(bytes));
            return this;
        }

        public Builder publicKey(String resource) {
            return publicKey(Classpath.bytesFrom(PPK.class, resource));
        }

        public Builder publicKey(Class<?> cls, String resource) {
            return publicKey(Classpath.bytesFrom(cls, resource));
        }

        public Builder publicKey(File file) {
            try {
                return publicKey(Files.readAllBytes(file.toPath()));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        public Builder privateKey(byte[] bytes) {
            privateCipher = Optional.of(readPrivateCipher(bytes));
            return this;
        }

        public Builder privateKey(String resource) {
            return privateKey(Classpath.bytesFrom(PPK.class, resource));
        }

        public Builder privateKey(Class<?> cls, String resource) {
            return privateKey(Classpath.bytesFrom(cls, resource));
        }

        public Builder privateKey(File file) {
            try {
                return privateKey(Files.readAllBytes(file.toPath()));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        public byte[] encrypt(byte[] bytes) {
            return build().encrypt(bytes);
        }

        public byte[] encrypt(InputStream is) {
            return build().encrypt(is);
        }

        public byte[] decrypt(byte[] bytes) {
            return build().decrypt(bytes);
        }

        public byte[] encrypt(String string, Charset charset) {
            return build().encrypt(string, charset);
        }

        public String decrypt(byte[] bytes, Charset charset) {
            return build().decrypt(bytes, charset);
        }

        public PPK build() {
            return new PPK(publicCipher, privateCipher);
        }

    }

    public byte[] encrypt(InputStream is) {
        try {
            return encrypt(ByteStreams.toByteArray(is));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] encrypt(byte[] bytes) {
        if (publicCipher.isPresent()) {
            byte[] rsaEncryptedAesSecretKeyBytes = applyCipher(publicCipher.get(), aesKey);
            ByteArrayOutputStream encrypted = new ByteArrayOutputStream();
            try {
                if (rsaEncryptedAesSecretKeyBytes.length > 256)
                    throw new RuntimeException(
                            "unexpected length=" + rsaEncryptedAesSecretKeyBytes.length);
                encrypted.write(rsaEncryptedAesSecretKeyBytes.length);
                encrypted.write(rsaEncryptedAesSecretKeyBytes);
                encryptWithAes(bytes, encrypted);
                encrypted.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return encrypted.toByteArray();
        } else
            throw new PublicKeyNotSetException();
    }

    private void encryptWithAes(byte[] bytes, OutputStream os) {
        try {
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKeySpec);
            ByteArrayInputStream is = new ByteArrayInputStream(bytes);
            applyCipher(aesCipher, is, os);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] decrypt(byte[] bytes) {
        if (privateCipher.isPresent()) {
            int rsaEncryptedAesSecretKeyLength;
            if (bytes[0] == 0)
                rsaEncryptedAesSecretKeyLength = 256;
            else
                rsaEncryptedAesSecretKeyLength = bytes[0];
            ByteArrayInputStream rsaEncryptedAesSecretKeyInputStream = new ByteArrayInputStream(
                    bytes, 1, rsaEncryptedAesSecretKeyLength);
            byte[] aesKey = new byte[AES_KEY_BYTES];
            try (CipherInputStream cis = new CipherInputStream(rsaEncryptedAesSecretKeyInputStream,
                    privateCipher.get())) {
                cis.read(aesKey, 0, rsaEncryptedAesSecretKeyLength);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            SecretKeySpec aesKeySpec = new SecretKeySpec(aesKey, AES);
            try {
                aesCipher.init(Cipher.DECRYPT_MODE, aesKeySpec);
                ByteArrayInputStream aesEncryptedBytes = new ByteArrayInputStream(bytes,
                        rsaEncryptedAesSecretKeyLength + 1,
                        bytes.length - rsaEncryptedAesSecretKeyLength - 1);
                ByteArrayOutputStream result = new ByteArrayOutputStream();
                applyCipher(aesCipher, aesEncryptedBytes, result);
                return result.toByteArray();
            } catch (InvalidKeyException e) {
                throw new RuntimeException(e);
            }
        } else
            throw new PrivateKeyNotSetException();
    }

    public byte[] encrypt(String string, Charset charset) {
        return encrypt(string.getBytes(charset));
    }

    public String decrypt(byte[] bytes, Charset charset) {
        return new String(decrypt(bytes), charset);
    }

    private static Cipher readPublicCipher(byte[] bytes) {
        try {
            X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(bytes);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA);
            PublicKey key = keyFactory.generatePublic(publicSpec);
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher;
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchPaddingException
                | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    private static Cipher readPrivateCipher(byte[] bytes) {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(RSA);
            PrivateKey key = keyFactory.generatePrivate(keySpec);
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher;
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchPaddingException
                | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] decrypt(Cipher cipher, byte[] bytes) {
        ByteArrayInputStream is = new ByteArrayInputStream(bytes);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        applyCipher(cipher, is, output);
        return output.toByteArray();
    }

    private static void applyCipher(Cipher cipher, InputStream is, OutputStream os) {
        try (CipherOutputStream cos = new CipherOutputStream(os, cipher)) {
            copy(is, cos);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] applyCipher(Cipher cipher, byte[] bytes) {
        ByteArrayInputStream input = new ByteArrayInputStream(bytes);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        applyCipher(cipher, input, output);
        return output.toByteArray();
    }

    private static void copy(InputStream is, OutputStream os) throws IOException {
        int i;
        byte[] b = new byte[1024];
        while ((i = is.read(b)) != -1) {
            os.write(b, 0, i);
        }
    }

}
