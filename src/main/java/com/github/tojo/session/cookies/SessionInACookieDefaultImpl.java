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

import org.apache.commons.codec.binary.Base64;

/**
 * Default implementation of {@link SessionInACookie}.
 * 
 * @author github.com/tojo
 */
class SessionInACookieDefaultImpl extends SessionInACookie {

	private final CipherStrategy cipherStrategy;
	private final SignatureStrategy signatureStrategy;

	// TODO Time-out strategies
	private TimeoutStrategy timeoutStrategy;
	// TODO Blacklist strategies
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
	 */
	public SessionInACookieDefaultImpl(CipherStrategy cipherStrategy,
			SignatureStrategy signatureStrategy) {
		this.cipherStrategy = cipherStrategy;
		this.signatureStrategy = signatureStrategy;
	}

	@Override
	String encode(byte[] data) throws CipherStrategyException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	byte[] decode(String cookieValue) throws TimeoutException,
			SignatureException, CipherStrategyException, BlacklistException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	void destroy(String cookieValue) {
		// TODO Auto-generated method stub

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
		byte[] signedSessionData = signatureStrategy
				.signAndPrefix(encryptedSessionData);

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
		byte[] encryptedSessionData = signatureStrategy
				.validateSignature(encryptedAndSignedSessionData);

		// 3. encrypt
		byte[] sessionData = cipherStrategy.decipher(encryptedSessionData);

		// return the decoded, decrypted and validated cookie value as session
		// data
		return sessionData;
	}
}