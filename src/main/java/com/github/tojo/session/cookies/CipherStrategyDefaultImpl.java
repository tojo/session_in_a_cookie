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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * TODO
 * 
 * @author github.com/tojo
 */
class CipherStrategyDefaultImpl implements CipherStrategy {

	static final String AES_ECB_PKCS5PADDING = "AES/CBC/PKCS5PADDING";
	static final String AES = "AES";
	static final String SHA_256 = "SHA-256";

	private byte[] secret;
	private IvParameterSpec ivspec;

	/**
	 * TODO
	 * 
	 * @param secret
	 * @param iv
	 */
	public CipherStrategyDefaultImpl(byte[] secret, byte[] iv) {
		super();
		this.secret = secret;
		this.ivspec = new IvParameterSpec(iv);
	}

	@Override
	public byte[] encipher(byte[] sessionData) throws CipherStrategyException {
		assertNotNullAndEmpty(sessionData);
		return encryptOrDecrypt(sessionData, Cipher.ENCRYPT_MODE);
	}

	@Override
	public byte[] decipher(byte[] cookieValue)
			throws CipherStrategyException {
		assertNotNullAndEmpty(cookieValue);
		return encryptOrDecrypt(cookieValue, Cipher.DECRYPT_MODE);
	}

	// /////////////////////////////////////////////////
	// non-public API
	// /////////////////////////////////////////////////

	private byte[] encryptOrDecrypt(byte[] input, int mode)
			throws CipherStrategyException {
		assertNotNullAndEmpty(input);

		byte[] output = null;
		try {
			Cipher cipher = Cipher.getInstance(AES_ECB_PKCS5PADDING);
			Key key = buildKey(secret, AES);
			cipher.init(mode, key, ivspec);
			output = cipher.doFinal(input);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException | InvalidAlgorithmParameterException e) {
			throw new CipherStrategyException(e);
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