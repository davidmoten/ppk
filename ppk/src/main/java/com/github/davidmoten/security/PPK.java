package com.github.davidmoten.security;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Optional;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import net.jcip.annotations.NotThreadSafe;

/**
 * Stands for Public Private Key. Might also have been called PKC (Public Key
 * Cryptography).
 */
@NotThreadSafe
public final class PPK {

	/*
	 * We load the public cipher and private cipher and we generate an AES cipher.
	 * The AES cipher is more efficient for encryption and decryption of data when
	 * the data can be longer than the RSA cipher key size. We use the public key to
	 * encrypt the AES cipher and prepend the AES encrypted bytes with the rsa
	 * encrypted AES secret key. Thus the consumer has to read the first N bytes and
	 * decrypt the AES secret key using the rsa private key and then can decrypt the
	 * remaining bytes in the message using the AES secret key.
	 */

	private static final String RSA_ALGORITHM = "RSA/ECB/OAEPWithSHA1AndMGF1Padding";
	private static final String RSA = "RSA";
	private static final String AES = "AES";
	private static final int AES_KEY_BITS = 128;// multiple of 8
	private static final int AES_KEY_BYTES = AES_KEY_BITS / 8;
	private final Optional<Cipher> publicCipher;
	private final Optional<Cipher> privateCipher;
	private final AesEncryption aes;
	private final boolean unique;

	private static class AesEncryption {
		// used just for encryption not for decryption
		final byte[] encodedSecretKey;

		// used just for encryption not decryption
		final SecretKeySpec secretKeySpec;

		// used for encryption and decryption
		final Cipher cipher;

		final Optional<byte[]> rsaEncryptedSecretKeyBytes;

		AesEncryption(Optional<Cipher> publicCipher) {
			try {
				KeyGenerator kgen = KeyGenerator.getInstance(AES);
				kgen.init(AES_KEY_BITS);
				SecretKey key = kgen.generateKey();
				encodedSecretKey = key.getEncoded();
				secretKeySpec = new SecretKeySpec(encodedSecretKey, AES);
				cipher = Cipher.getInstance(AES);
				if (publicCipher.isPresent()) {
					rsaEncryptedSecretKeyBytes = Optional.of(applyCipher(publicCipher.get(), encodedSecretKey));
					if (rsaEncryptedSecretKeyBytes.get().length > 256)
						throw new RuntimeException("unexpected length=" + rsaEncryptedSecretKeyBytes.get().length);
				} else
					rsaEncryptedSecretKeyBytes = Optional.empty();
			} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
				throw new RuntimeException(e);
			}
		}

	}

	private PPK(Optional<Cipher> publicCipher, Optional<Cipher> privateCipher, boolean unique) {
		this.publicCipher = publicCipher;
		this.privateCipher = privateCipher;
		this.aes = new AesEncryption(publicCipher);
		this.unique = unique;
	}

	/**
	 * Returns a builder having loaded the private key from the classpath relative
	 * to the classloader used by {@code cls}.
	 * 
	 * @param cls      the class whose classloader is used to load the resource
	 * @param resource the resource path
	 * @return the PPK builder
	 */
	public static final Builder privateKey(Class<?> cls, String resource) {
		return new Builder().privateKey(cls, resource);
	}

	/**
	 * Returns a PPK builder having set the private key location on the classpath
	 * relative to the classloader used by {@link PPK}.
	 * 
	 * @param resource the resource path
	 * @return the PPK builder
	 */
	public static final Builder privateKey(String resource) {
		return new Builder().privateKey(resource);
	}

	/**
	 * Returns a PPK builder having read the private key from the given InputStream.
	 * 
	 * @param is private key input stream
	 * @return the PPK builder
	 */
	public static final Builder privateKey(InputStream is) {
		return new Builder().privateKey(is);
	}

	/**
	 * Returns a PPK builder having read the private key from the given file.
	 * 
	 * @param file that contains the private key
	 * @return the PPK builder
	 */
	public static final Builder privateKey(File file) {
		return new Builder().privateKey(file);
	}

	public static final Builder privateKeyB64(File file) {
		return new Builder().privateKeyB64(file);
	}

	public static final Builder publicKeyB64(File file) {
		return new Builder().publicKeyB64(file);
	}

	/**
	 * Returns a PPK builder having read the private key from the given byte array.
	 * 
	 * @param bytes of the private key
	 * @return the PPK builder
	 */
	public static final Builder privateKey(byte[] bytes) {
		return new Builder().privateKey(bytes);
	}

	/**
	 * Returns a builder having loaded the public key from the classpath relative to
	 * the classloader used by {@code cls}.
	 * 
	 * @param cls      the class whose classloader is used to load the resource
	 * @param resource the resource path
	 * @return the PPK builder
	 */
	public static final Builder publicKey(Class<?> cls, String resource) {
		return new Builder().publicKey(cls, resource);
	}

	/**
	 * Returns a builder having loaded the public key from the classpath relative to
	 * the classloader used by {@link PPK}.
	 * 
	 * @param resource the resource path
	 * @return the PPK builder
	 */
	public static final Builder publicKey(String resource) {
		return new Builder().publicKey(resource);
	}

	public static final Builder publicKey(File file) {
		return new Builder().publicKey(file);
	}

	public static final Builder publicKey(InputStream is) {
		return new Builder().publicKey(is);
	}

	public static final Builder publicKey(byte[] bytes) {
		return new Builder().publicKey(bytes);
	}

	public static final class Builder {
		private Optional<Cipher> publicCipher = Optional.empty();
		private Optional<Cipher> privateCipher = Optional.empty();
		private boolean unique = false;

		private Builder() {
			// prevent instantiation
		}

		public Builder publicKeyB64(File file) {
			return publicKey(bytesFromB64(file));
		}

		public Builder privateKeyB64(File file) {
			return privateKey(bytesFromB64(file));
		}

		public Builder publicKey(InputStream is) {
			Preconditions.checkNotNull(is);
			return publicKey(Bytes.from(is));
		}

		public Builder privateKey(InputStream is) {
			Preconditions.checkNotNull(is);
			return privateKey(Bytes.from(is));
		}

		public Builder publicKey(byte[] bytes) {
			Preconditions.checkNotNull(bytes);
			publicCipher = Optional.of(readPublicCipher(bytes));
			return this;
		}

		public Builder publicKey(String resource) {
			Preconditions.checkNotNull(resource);
			return publicKey(Classpath.bytesFrom(PPK.class, resource));
		}

		public Builder publicKey(Class<?> cls, String resource) {
			Preconditions.checkNotNull(cls);
			Preconditions.checkNotNull(resource);
			return publicKey(Classpath.bytesFrom(cls, resource));
		}

		public Builder publicKey(File file) {
			Preconditions.checkNotNull(file);
			try {
				return publicKey(Files.readAllBytes(file.toPath()));
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}

		public Builder privateKey(byte[] bytes) {
			Preconditions.checkNotNull(bytes);
			privateCipher = Optional.of(readPrivateCipher(bytes));
			return this;
		}

		public Builder privateKey(String resource) {
			Preconditions.checkNotNull(resource);
			return privateKey(Classpath.bytesFrom(PPK.class, resource));
		}

		public Builder privateKey(Class<?> cls, String resource) {
			Preconditions.checkNotNull(cls);
			Preconditions.checkNotNull(resource);
			return privateKey(Classpath.bytesFrom(cls, resource));
		}

		public Builder privateKey(File file) {
			Preconditions.checkNotNull(file);
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

		public byte[] encryptRsa(byte[] bytes) {
			return build().encryptRsa(bytes);
		}

		public byte[] encryptRsa(String string, Charset charset) {
			return build().encryptRsa(string, charset);
		}

		public String encryptAsBase64(String string) {
			return build().encryptAsBase64(string);
		}

		public String encryptRsaAsBase64(String string) {
			return build().encryptRsaAsBase64(string);
		}

		public String decrypt(byte[] bytes, Charset charset) {
			return build().decrypt(bytes, charset);
		}

		public byte[] decryptRsa(byte[] bytes) {
			return build().decryptRsa(bytes);
		}

		public String decryptRsa(byte[] bytes, Charset charset) {
			return build().decryptRsa(bytes, charset);
		}

		public String decryptRsaBase64(String base64) {
			return build().decryptRsaBase64(base64);
		}

		public String decryptBase64(String base64) {
			return build().decryptBase64(base64);
		}

		public void encrypt(InputStream is, OutputStream os) {
			build().encrypt(is, os);
		}

		public void decrypt(InputStream is, OutputStream os) {
			build().decrypt(is, os);
		}

		public Builder unique(boolean value) {
			this.unique = value;
			return this;
		}

		public Builder unique() {
			return unique(true);
		}

		public PPK build() {
			return new PPK(publicCipher, privateCipher, unique);
		}

	}

	public void encrypt(InputStream is, OutputStream os) {
		Preconditions.checkNotNull(is);
		Preconditions.checkNotNull(os);
		if (publicCipher.isPresent()) {
			try {
				final AesEncryption aes;
				if (unique) {
					aes = new AesEncryption(publicCipher);
				} else {
					aes = this.aes;
				}
				os.write(aes.rsaEncryptedSecretKeyBytes.get().length - 1);
				os.write(aes.rsaEncryptedSecretKeyBytes.get());
				encryptWithAes(aes, is, os);
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		} else
			throw new PublicKeyNotSetException();
	}

	public String encryptAsBase64(String string) {
		return Base64.getEncoder().encodeToString(encrypt(string, UTF_8));
	}

	public String decryptBase64(String base64) {
		return decrypt(Base64.getDecoder().decode(base64), UTF_8);
	}

	public byte[] encrypt(InputStream is) {
		Preconditions.checkNotNull(is);
		return encrypt(Bytes.from(is));
	}

	public byte[] encrypt(byte[] bytes) {
		Preconditions.checkNotNull(bytes);
		try (ByteArrayInputStream is = new ByteArrayInputStream(bytes);
				ByteArrayOutputStream os = new ByteArrayOutputStream()) {
			encrypt(is, os);
			return os.toByteArray();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private static void encryptWithAes(AesEncryption aes, InputStream is, OutputStream os) {
		Preconditions.checkNotNull(is);
		Preconditions.checkNotNull(os);
		try {
			aes.cipher.init(Cipher.ENCRYPT_MODE, aes.secretKeySpec);
			applyCipher(aes.cipher, is, os);
		} catch (InvalidKeyException e) {
			throw new RuntimeException(e);
		}
	}

	public void decrypt(InputStream is, OutputStream os) {
		Preconditions.checkNotNull(is);
		Preconditions.checkNotNull(os);
		if (privateCipher.isPresent()) {
			int rsaEncryptedAesSecretKeyLength;
			byte[] raw;
			try {
				rsaEncryptedAesSecretKeyLength = is.read() + 1;
				raw = read(is, rsaEncryptedAesSecretKeyLength);
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
			ByteArrayInputStream rsaEncryptedAesSecretKeyInputStream = new ByteArrayInputStream(raw);
			byte[] aesKey = new byte[AES_KEY_BYTES];
			try (CipherInputStream cis = new CipherInputStream(rsaEncryptedAesSecretKeyInputStream,
					privateCipher.get())) {
				cis.read(aesKey, 0, rsaEncryptedAesSecretKeyLength);
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
			SecretKeySpec aesKeySpec = new SecretKeySpec(aesKey, AES);
			try {
				aes.cipher.init(Cipher.DECRYPT_MODE, aesKeySpec);
				applyCipher(aes.cipher, is, os);
			} catch (InvalidKeyException e) {
				throw new RuntimeException(e);
			}
		} else
			throw new PrivateKeyNotSetException();
	}

	private static byte[] read(InputStream is, int numBytes) {
		byte[] b = new byte[numBytes];
		int i = 0;
		try {
			int n;
			while (i < numBytes && (n = is.read(b, i, numBytes - i)) != -1) {
				i += n;
			}
			return b;
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}

	}

	public byte[] decrypt(byte[] bytes) {
		Preconditions.checkNotNull(bytes);
		try (InputStream is = new ByteArrayInputStream(bytes); ByteArrayOutputStream os = new ByteArrayOutputStream()) {
			decrypt(is, os);
			return os.toByteArray();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public byte[] encrypt(String string, Charset charset) {
		Preconditions.checkNotNull(string);
		Preconditions.checkNotNull(charset);
		return encrypt(string.getBytes(charset));
	}

	public String decrypt(byte[] bytes, Charset charset) {
		Preconditions.checkNotNull(bytes);
		Preconditions.checkNotNull(charset);
		return new String(decrypt(bytes), charset);
	}

	public byte[] encryptRsa(byte[] bytes) {
		Preconditions.checkNotNull(bytes);
		if (bytes.length > 214) {
			throw new InputTooLongException(
					"Input is too long. Use encrypt()/decrypt() instead because RSA cannot encrypt more than 214 bytes.");
		}
		return applyCipher(publicCipher.get(), bytes);
	}

	public byte[] decryptRsa(byte[] bytes) {
		Preconditions.checkNotNull(bytes);
		return applyCipher(privateCipher.get(), bytes);
	}

	public byte[] encryptRsa(String string, Charset charset) {
		Preconditions.checkNotNull(string);
		Preconditions.checkNotNull(charset);
		return encryptRsa(string.getBytes(charset));
	}

	public String encryptRsaAsBase64(String string) {
		return Base64.getEncoder().encodeToString(encryptRsa(string, UTF_8));
	}

	public String decryptRsa(byte[] bytes, Charset charset) {
		Preconditions.checkNotNull(bytes);
		Preconditions.checkNotNull(charset);
		return new String(decryptRsa(bytes), charset);
	}

	public String decryptRsaBase64(String base64) {
		return decryptRsa(Base64.getDecoder().decode(base64), UTF_8);
	}

	private static Cipher readPublicCipher(byte[] bytes) {
		try {
			X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(bytes);
			KeyFactory keyFactory = KeyFactory.getInstance(RSA);
			PublicKey key = keyFactory.generatePublic(publicSpec);
			Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
			cipher.init(Cipher.ENCRYPT_MODE, key);
			return cipher;
		} catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
			throw new RuntimeException(e);
		}
	}

	private static Cipher readPrivateCipher(byte[] bytes) {
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
		try {
			KeyFactory keyFactory = KeyFactory.getInstance(RSA);
			PrivateKey key = keyFactory.generatePrivate(keySpec);
			Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
			cipher.init(Cipher.DECRYPT_MODE, key);
			return cipher;
		} catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
			throw new RuntimeException(e);
		}
	}

	private static void applyCipher(Cipher cipher, InputStream is, OutputStream os) {
		try (CipherOutputStream cos = new CipherOutputStream(os, cipher)) {
			copy(is, cos);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private static byte[] applyCipher(Cipher cipher, byte[] bytes) {
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

	public static KeyPair createKeyPair() {
		KeyPairGenerator gen;
		try {
			gen = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
		gen.initialize(2048);
		java.security.KeyPair kp = gen.generateKeyPair();
		return new KeyPair(kp.getPrivate().getEncoded(), kp.getPublic().getEncoded());
	}

	private static byte[] bytesFromB64(File file) {
		try {
			byte[] b64 = Files.readAllBytes(file.toPath());
			return Base64.getDecoder().decode(b64);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

}
