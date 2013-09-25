/**
 * The MIT License (MIT)
 * 
 * Copyright (c) 2013 tojo
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package com.github.tojo.session.cookies;

import static com.github.tojo.session.cookies.SessionInACookie.assertNotNullAndEmpty;

import java.lang.reflect.Field;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang.ArrayUtils;

/**
 * Default implementation of {@link CipherStrategy}.
 * 
 * @author github.com/tojo
 */
class CipherStrategyDefaultImpl implements CipherStrategy {

	static final String AES_CTR_PKCS5PADDING = "AES/CTR/PKCS5PADDING";
	static final String AES = "AES";
	static final String SHA_256 = "SHA-256";

	private final IvParameterSpec ivspec;
	private final Key key;

	/**
	 * Constructor
	 * 
	 * @param secret
	 *            shared secret for en-/decryption
	 */
	public CipherStrategyDefaultImpl(byte[] secret) {
		super();

		try {
			Class<?> securityClass = java.lang.Class
					.forName("javax.crypto.JceSecurity");
			Field restrictedField = securityClass
					.getDeclaredField("isRestricted");
			restrictedField.setAccessible(true);
			restrictedField.set(null, false);
		} catch (ClassNotFoundException | NoSuchFieldException
				| SecurityException | IllegalArgumentException
				| IllegalAccessException e) {
			throw new CipherStrategyException(
					"Disable the crypto restriction programmatically faild!", e);
		}

		this.ivspec = new IvParameterSpec(ArrayUtils.subarray(UUID.randomUUID()
				.toString().getBytes(), 0, 16));
		;
		try {
			this.key = buildKey(secret, AES);
		} catch (NoSuchAlgorithmException e) {
			throw new InitializationError(e);
		}
	}

	@Override
	public byte[] encipher(byte[] sessionData) throws CipherStrategyException {
		assertNotNullAndEmpty(sessionData);
		return encryptOrDecrypt(sessionData, Cipher.ENCRYPT_MODE);
	}

	@Override
	public byte[] decipher(byte[] cookieValue) {
		assertNotNullAndEmpty(cookieValue);
		return encryptOrDecrypt(cookieValue, Cipher.DECRYPT_MODE);
	}

	// /////////////////////////////////////////////////
	// non-public API
	// /////////////////////////////////////////////////

	private byte[] encryptOrDecrypt(byte[] input, int mode) {
		assertNotNullAndEmpty(input);

		byte[] output = null;
		try {
			Cipher cipher = Cipher.getInstance(AES_CTR_PKCS5PADDING);
			cipher.init(mode, key, ivspec);
			output = cipher.doFinal(input);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException | InvalidAlgorithmParameterException e) {
			throw new CipherStrategyException(
					(mode == Cipher.ENCRYPT_MODE ? "Encryption" : "Decryption")
							+ " failed!", e);
		}
		return output;
	}

	private Key buildKey(byte[] key, String algorithmus)
			throws NoSuchAlgorithmException {
		assertNotNullAndEmpty(key);
		MessageDigest digester = MessageDigest.getInstance(SHA_256);
		digester.update(key);
		SecretKeySpec spec = new SecretKeySpec(digester.digest(), algorithmus);
		return spec;
	}
}