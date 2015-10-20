package com.github.davidmoten.security;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.google.common.io.ByteStreams;

public final class PPK {

    private final Optional<PublicKey> publicKey;
    private final Optional<PrivateKey> privateKey;

    private PPK(Optional<PublicKey> publicKey, Optional<PrivateKey> privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
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
        private Optional<PublicKey> publicKey = Optional.empty();
        private Optional<PrivateKey> privateKey = Optional.empty();

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
            publicKey = Optional.of(readPublicKey(bytes));
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
            privateKey = Optional.of(readPrivateKey(bytes));
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
            return new PPK(publicKey, privateKey);
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
        return encrypt(publicKey.get(), bytes);
    }

    public byte[] decrypt(byte[] bytes) {
        return decrypt(privateKey.get(), bytes);
    }

    public byte[] encrypt(String string, Charset charset) {
        return encrypt(string.getBytes(charset));
    }

    public String decrypt(byte[] bytes, Charset charset) {
        return new String(decrypt(bytes), charset);
    }

    private static PublicKey readPublicKey(byte[] bytes) {
        try {
            X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(bytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(publicSpec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static PrivateKey readPrivateKey(byte[] bytes) {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] encrypt(PublicKey key, byte[] plaintext) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(plaintext);
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException
                | NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] decrypt(PrivateKey key, byte[] ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(ciphertext);
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException
                | NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }

}
