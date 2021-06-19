package com.aws.pass.encrypt;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EncryptionUtil {

	private static final Logger LOGGER = LoggerFactory.getLogger(EncryptionUtil.class);

	private static final String KEY = "rMcQIVVLNrkhr8l0ASC38k1ngvKvzxdv";

	private static final String AES = "AES";
	private static final String UTF_8 = StandardCharsets.UTF_8.name();
	private static final String EMESSAGE = "Error while encrypting String ";
	private static final String DMESSAGE = "Error while decrypting String ";
	private static final String KMESSAGE = "No Key value provided. Default key will be used.";
	private static final String WMESSAGE = " with key ";
	private static final String EMPTY_STRING = "";
	
	public static void main(String[] args) throws EncryptionException {
		System.out.println(EncryptionUtil.encrypt("HelloWorld"));
		System.out.println(EncryptionUtil.decrypt("DE1RXLDs1F9fqrNy1EEdWA=="));
	}

	private EncryptionUtil() {
	}

	public static String encrypt(String plainText) throws EncryptionException {
		try {
			return encryptStringAES(plainText);
		} catch (Exception e) {
			throw new EncryptionException(EMESSAGE + plainText + " " + e);
		}
	}

	public static String encrypt(String key, String plainText) throws EncryptionException {
		try {
			return encryptStringAES(key, plainText);
		} catch (Exception e) {
			throw new EncryptionException(EMESSAGE + plainText + WMESSAGE + key + " " + e);
		}
	}

	public static String decrypt(String encryptedText) throws EncryptionException {
		try {
			return decryptStringAES(encryptedText);
		} catch (Exception e) {
			throw new EncryptionException(DMESSAGE + encryptedText + " " + e);
		}
	}

	public static String decrypt(String key, String encryptedText) throws EncryptionException {
		try {
			return decryptStringAES(key, encryptedText);
		} catch (Exception e) {
			throw new EncryptionException(DMESSAGE + encryptedText + WMESSAGE + key + " " + e);
		}
	}

	private static String encryptStringAES(String plainText) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
		return encryptStringAES(KEY, plainText);
	}

	private static String encryptStringAES(final String key, final String plainText)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, UnsupportedEncodingException {

		// Instantiate the cipherH
		Cipher cipher = Cipher.getInstance(AES);
		cipher.init(Cipher.ENCRYPT_MODE, getSpec(key));

		byte[] encryptedTextBytes = cipher.doFinal(plainText.getBytes(UTF_8));

		return new String(Base64.getEncoder().encode(encryptedTextBytes));
	}

	private static String decryptStringAES(String encryptedText)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, UnsupportedEncodingException {
		return decryptStringAES(KEY, encryptedText);
	}

	private static String decryptStringAES(String key, String encryptedText)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, UnsupportedEncodingException {

		// Instantiate the cipher
		Cipher cipher = Cipher.getInstance(AES);
		cipher.init(Cipher.DECRYPT_MODE, getSpec(key));

		LOGGER.info("encryptedString: /////////////////");
		LOGGER.info("encryptedString: " + encryptedText);

		byte[] encryptedTextBytes = Base64.getDecoder().decode(encryptedText);
		byte[] decryptedTextBytes = cipher.doFinal(encryptedTextBytes);

		return new String(decryptedTextBytes);
	}

	private static SecretKeySpec getSpec(String key) throws UnsupportedEncodingException {
		String key1 = key;
		SecretKeySpec keySpec = null;
		if (key1 == null || key1.trim().equals(EMPTY_STRING)) {
			LOGGER.warn(KMESSAGE);
			keySpec = new SecretKeySpec(KEY.getBytes(UTF_8), AES);
		} else {
			keySpec = new SecretKeySpec(key1.getBytes(UTF_8), AES);
		}
		return keySpec;
	}

}
