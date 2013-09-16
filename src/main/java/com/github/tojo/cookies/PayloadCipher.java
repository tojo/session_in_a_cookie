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
package com.github.tojo.cookies;

/**
 * Methods to encrypt and decrypt of user data.
 * 
 * @author github.com/tojo
 */
public interface PayloadCipher {

	/**
	 * This method takes as an argument the unencrypted payload and returns
	 * encrypted.
	 * 
	 * @param rawPayload
	 *            The unencrypted user data to be encrypted.
	 * @return The encrypted payload.
	 * @throws IllegalArgumentException
	 *             if the rawPayload is null or empty
	 */
	byte[] encipher(byte[] rawPayload);

	/**
	 * This method takes as an argument the encrypted payload, decrypts it and
	 * returns it.
	 * 
	 * @param encryptedPayload
	 *            The encrypted payload, which are to be decoded.
	 * @return The decoded payload.
	 * @throws IllegalArgumentException
	 *             if the encryptedPayload is null or empty
	 */
	byte[] decipher(byte[] encryptedPayload);
}
