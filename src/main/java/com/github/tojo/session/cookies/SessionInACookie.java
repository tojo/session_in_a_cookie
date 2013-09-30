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

/**
 * Helper methods for implementing the session-in-a-cookie pattern.
 * 
 * @author github.com/tojo
 */
public abstract class SessionInACookie {

	private static SessionInACookie instance = null;

	final CipherStrategy cipherStrategy;
	final SignatureStrategy signatureStrategy;
	final TimeoutStrategy timeoutStrategy;
	final BlacklistStrategy blacklistStrategy;

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
	public SessionInACookie(CipherStrategy cipherStrategy,
			SignatureStrategy signatureStrategy,
			TimeoutStrategy timeoutStrategy, BlacklistStrategy blacklistStrategy) {
		this.cipherStrategy = cipherStrategy;
		this.signatureStrategy = signatureStrategy;
		this.timeoutStrategy = timeoutStrategy;
		this.blacklistStrategy = blacklistStrategy;
	}

	/**
	 * Returns the value which has to be stored in the session-in-a-cookie for
	 * the given session data.
	 * 
	 * The session data will be prefixed with a unique session id, encryped
	 * through {@link CipherStrategy#encipher(byte[])}, signed by
	 * {@link SignatureStrategy#sign(byte[])} and finally Base64 encoded.
	 * 
	 * @param sessionData
	 *            the serialized session-in-a-cookie session data
	 * 
	 * @return the value of the session-in-a-cookie cookie
	 * @throws CipherStrategyException
	 *             if the session data couldn't be encrypted
	 */
	public abstract CookieValue encode(SessionData sessionData)
			throws CipherStrategyException;

	/**
	 * This method checks the blacklist {@link BlacklistStrategy#check(String)},
	 * advance the timeout {@link TimeoutStrategy#advance(String)} and decode
	 * the serialized session-in-a-cookie session data.
	 * 
	 * @param cookieValue
	 *            the value of the session-in-a-cookie cookie
	 * 
	 * @return the serialized session-in-a-cookie session data
	 * @throws TimeoutException
	 *             if the session has timed out
	 * @throws SignatureException
	 *             if the signature is invalid
	 * @throws CipherStrategyException
	 *             if the session data couldn't be decrypted
	 * @throws BlacklistException
	 *             if the session has been blacklisted
	 * @throws InvalidInputFormatException
	 *             if the cookieValue is null or empty
	 */
	public abstract byte[] decode(CookieValue cookieValue)
			throws TimeoutException, SignatureException, BlacklistException;

	public CipherStrategy getCipherStrategy() {
		return cipherStrategy;
	}

	public SignatureStrategy getSignatureStrategy() {
		return signatureStrategy;
	}

	public TimeoutStrategy getTimeoutStrategy() {
		return timeoutStrategy;
	}

	public BlacklistStrategy getBlacklistStrategy() {
		return blacklistStrategy;
	}

	/**
	 * Get the default {@link SessionInACookie} implementation object.
	 * 
	 * @param secret
	 *            the shared secret for en- and decryption.
	 * @return the default {@link SessionInACookie} object
	 */
	public static SessionInACookie getDefaultInstance(byte[] secret) {
		// not multi-threading safe
		if (instance == null) {
			instance = new SessionInACookieDefaultImpl(
					new CipherStrategyDefaultImpl(secret),
					new SignatureStrategyDefaultImpl(secret),
					new TimeoutStrategyDefaultImpl(),
					new BlacklistStrategyDefaultImpl());
		}
		return instance;
	}

	/**
	 * Get the default {@link SessionInACookie} implementation object.
	 * 
	 * @param secret
	 *            the shared secret for en- and decryption.
	 * @param timeoutStrategy
	 * @param blacklistStrategy
	 * @return the default {@link SessionInACookie} object
	 */
	public static SessionInACookie getDefaultInstance(byte[] secret,
			TimeoutStrategy timeoutStrategy, BlacklistStrategy blacklistStrategy) {
		if (instance == null) {
			instance = new SessionInACookieDefaultImpl(
					new CipherStrategyDefaultImpl(secret),
					new SignatureStrategyDefaultImpl(secret), timeoutStrategy,
					blacklistStrategy);
		}
		return instance;
	}

	// /////////////////////////////////////////////////
	// non-public API
	// /////////////////////////////////////////////////

	static void assertNotNullAndEmpty(byte[] input) {
		if (input == null || input.length == 0)
			throw new InvalidInputFormatException(
					"Input byte[] is null or empty!");
	}

	static void assertMinLength(byte[] input, int minLength) {
		assertNotNullAndEmpty(input);
		if (minLength > input.length)
			throw new InvalidInputFormatException(
					"Input byte[] is to short! The length must be at least "
							+ minLength);
	}
}
