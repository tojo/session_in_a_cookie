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

	/**
	 * TODO
	 * 
	 * @param sessionData
	 *            the serialized session-in-a-cookie session data
	 * 
	 * @return the value of the session-in-a-cookie cookie
	 * @throws CipherStrategyException
	 */
	abstract String encode(byte[] sessionData) throws CipherStrategyException;

	/**
	 * TODO
	 * 
	 * @param cookieValue
	 *            the value of the session-in-a-cookie cookie
	 * 
	 * @return the serialized session-in-a-cookie session data
	 * @throws TimeoutException
	 * @throws SignatureException
	 * @throws CipherStrategyException
	 * @throws BlacklistException
	 * @throws IllegalArgumentException
	 *             if the cookieValue is null or empty
	 */
	abstract byte[] decode(String cookieValue) throws TimeoutException,
			SignatureException, CipherStrategyException, BlacklistException;

	/**
	 * TODO
	 * 
	 * @param cookieValue
	 *            the value of the session-in-a-cookie cookie
	 * @throws IllegalArgumentException
	 *             if the cookieValue is null or empty
	 */
	abstract void destroy(String cookieValue);

	/**
	 * Get the default {@link SessionInACookie} implementation object.
	 * 
	 * @param secret
	 *            the shared secret for en- and decryption.
	 * @param iv
	 *            initial vector for en- and decryption
	 * @return the default {@link SessionInACookie} object
	 */
	public static SessionInACookie getDefaultInstance(byte[] secret, byte[] iv) {
		if (instance == null) {
			instance = new SessionInACookieDefaultImpl(
					new CipherStrategyDefaultImpl(secret, iv),
					new SignatureStrategyDefaultImpl(secret), new TimeoutStrategyDefaultImpl(), new BlacklistStrategyDefaultImpl());
		}
		return instance;
	}

	// /////////////////////////////////////////////////
	// non-public API
	// /////////////////////////////////////////////////

	static void assertNotNullAndEmpty(byte[] input) {
		if (input == null || input.length == 0)
			throw new IllegalArgumentException("Input byte[] is null or empty!");
	}

	static void assertMinLength(byte[] input, int minLength) {
		assertNotNullAndEmpty(input);
		if (minLength > input.length)
			throw new IllegalArgumentException(
					"Input byte[] is to short! The length must be at least "
							+ minLength);
	}
}