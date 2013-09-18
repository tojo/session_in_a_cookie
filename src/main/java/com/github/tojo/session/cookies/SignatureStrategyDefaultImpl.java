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

import static com.github.tojo.session.cookies.SessionInACookie.assertMinLength;
import static com.github.tojo.session.cookies.SessionInACookie.assertNotNullAndEmpty;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang.ArrayUtils;

/**
 * TODO
 * 
 * @author github.com/tojo
 */
class SignatureStrategyDefaultImpl implements SignatureStrategy {

	static final String SHA_256 = "SHA-256";
	static final int SIGNATURE_LENGTH = 32;
	static final String HMAC_SHA256 = "HmacSHA256";

	private final Key key;

	/**
	 * TODO
	 * 
	 * @param secret
	 */
	public SignatureStrategyDefaultImpl(byte[] secret) {
		try {
			this.key = buildKey(secret, HMAC_SHA256);
		} catch (NoSuchAlgorithmException e) {
			throw new InitializationError(e);
		}
	}

	@Override
	public byte[] sign(byte[] sessionData) {
		assertNotNullAndEmpty(sessionData);

		byte[] signature = null;
		try {
			Mac mac = Mac.getInstance(HMAC_SHA256);
			mac.init(key);
			signature = mac.doFinal(sessionData);
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			throw new RuntimeException(e);
		}
		return signature;
	}

	@Override
	public void validateSignature(byte[] sessionData, byte[] signature)
			throws SignatureException {
		assertNotNullAndEmpty(sessionData);
		assertMinLength(signature, SIGNATURE_LENGTH);

		if (SIGNATURE_LENGTH != signature.length) {
			throw new SignatureException("Invalid signature length. Expected: "
					+ SIGNATURE_LENGTH + ", is: " + signature.length);
		}
		byte[] newSignature = sign(sessionData);
		if (!Arrays.equals(newSignature, signature)) {
			throw new SignatureException("Invalid signature!");
		}
	}

	@Override
	public int getSignatureLength() {
		return SIGNATURE_LENGTH;
	}

	// /////////////////////////////////////////////////
	// non-public API
	// /////////////////////////////////////////////////

	byte[] signAndPrefix(byte[] sessionData) {
		assertNotNullAndEmpty(sessionData);

		byte[] signature = sign(sessionData);
		byte[] signedSessionData = ArrayUtils.addAll(signature, sessionData);
		return signedSessionData;
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