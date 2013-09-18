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

import java.io.UnsupportedEncodingException;
import java.util.UUID;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.ArrayUtils;

/**
 * Default implementation of {@link SessionInACookie}.
 * 
 * @author github.com/tojo
 */
class SessionInACookieDefaultImpl extends SessionInACookie {

	private static final int SESSION_ID_LENGTH = 36;
	private final CipherStrategy cipherStrategy;
	private final SignatureStrategy signatureStrategy;
	private TimeoutStrategy timeoutStrategy;
	private BlacklistStrategy blacklistStrategy;

	// TODO Transformer strategies

	/**
	 * Constructor
	 * 
	 * @param secret
	 *            shared secret for en-/decryption
	 * @param iv
	 *            initial vector for en-/decryption
	 * @param cipherStrategy
	 * @param signatureStrategy
	 * @param timeoutStrategy
	 * @param blacklistStrategy
	 */
	public SessionInACookieDefaultImpl(CipherStrategy cipherStrategy,
			SignatureStrategy signatureStrategy,
			TimeoutStrategy timeoutStrategy, BlacklistStrategy blacklistStrategy) {
		this.cipherStrategy = cipherStrategy;
		this.signatureStrategy = signatureStrategy;
		this.timeoutStrategy = timeoutStrategy;
		this.blacklistStrategy = blacklistStrategy;
	}

	@Override
	String encode(byte[] sessionData) throws CipherStrategyException {
		try {
			// 1. create session id
			byte[] sessionId = UUID.randomUUID().toString().getBytes("UTF-8");

			// 2. prefix session data with the session id
			byte[] dataWithSessionId = ArrayUtils
					.addAll(sessionId, sessionData);

			// 3. calculate the cookie value
			String cookieValue = new String(
					encryptSignAndEncode(dataWithSessionId), "UTF-8");

			// 4. hit timeout strategy
			timeoutStrategy.hit(cookieValue);

			return cookieValue;
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	byte[] decode(String cookieValue) throws TimeoutException,
			SignatureException, CipherStrategyException, BlacklistException {

		try {
			// 1. check blacklist
			blacklistStrategy.check(cookieValue);

			// 2. hit timeout
			timeoutStrategy.hit(cookieValue);

			// 3. decode
			byte[] dataWithSessionId;
			dataWithSessionId = decodeDecryptAndVerifySignature(cookieValue
					.getBytes("UTF-8"));

			// 4. extract the session id
			byte[] sessionId = ArrayUtils.subarray(dataWithSessionId, 0,
					SESSION_ID_LENGTH);

			// 5. extract the session data
			byte[] sessionData = ArrayUtils.subarray(dataWithSessionId,
					SESSION_ID_LENGTH, dataWithSessionId.length);

			// 3. return the session data
			return sessionData;
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	void destroy(String cookieValue) {
		timeoutStrategy.timeout(cookieValue);
	}

	// /////////////////////////////////////////////////
	// non-public API
	// /////////////////////////////////////////////////

	byte[] encryptSignAndEncode(byte[] sessionData)
			throws CipherStrategyException {
		assertNotNullAndEmpty(sessionData);

		// 1. encrypt
		byte[] encryptedSessionData = cipherStrategy.encipher(sessionData);

		// 2. sign
		byte[] signature = signatureStrategy.sign(encryptedSessionData);
		byte[] signedSessionData = ArrayUtils.addAll(signature,
				encryptedSessionData);

		// 3. decode
		byte[] cookieValue = Base64.encodeBase64(signedSessionData);

		// return the encrypted, signed and base64 encoded session data as
		// cookie value
		return cookieValue;
	}

	byte[] decodeDecryptAndVerifySignature(byte[] cookieValue)
			throws SignatureException, CipherStrategyException {
		assertNotNullAndEmpty(cookieValue);

		// 1. decode
		byte[] encryptedAndSignedSessionData = Base64.decodeBase64(cookieValue);

		// 2. validate signature
		byte[] signature = ArrayUtils.subarray(encryptedAndSignedSessionData,
				0, signatureStrategy.getSignatureLength());
		byte[] encryptedSessionData = ArrayUtils.subarray(
				encryptedAndSignedSessionData,
				signatureStrategy.getSignatureLength(),
				encryptedAndSignedSessionData.length);
		signatureStrategy.validateSignature(encryptedSessionData, signature);

		// 3. encrypt
		byte[] sessionData = cipherStrategy.decipher(encryptedSessionData);

		// return the decoded, decrypted and validated cookie value as session
		// data
		return sessionData;
	}
}