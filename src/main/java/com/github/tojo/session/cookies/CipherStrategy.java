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
 * Methods to encrypt session data and decrypt cookie values.
 * 
 * @author github.com/tojo
 */
public interface CipherStrategy {

	/**
	 * This method takes as an argument the raw session data and returns the
	 * encrypted cookie value.
	 * 
	 * @param sessionData
	 *            the raw session data
	 * @return the encrypted cookie value.
	 * @throws CipherStrategyException
	 *             if the session data couldn't be encrypted
	 * @throws InvalidInputFormatException
	 *             if the sessionData is null or empty
	 */
	byte[] encipher(byte[] sessionData) throws CipherStrategyException;

	/**
	 * This method takes as an argument the encrypted cookie value, decrypts the
	 * session data and returns it.
	 * 
	 * @param cookieValue
	 *            The encrypted cookie value.
	 * @return The raw session data.
	 * @throws CipherStrategyException
	 *             if the cookieValue couldn't be decrypted
	 * @throws InvalidInputFormatException
	 *             if the cookieValue is null or empty
	 */
	byte[] decipher(byte[] cookieValue);
}
