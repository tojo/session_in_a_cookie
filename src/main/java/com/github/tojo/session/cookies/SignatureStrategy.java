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
 * Methods to create and verify signatures. This is useful to check the data
 * integrity and make sure that the session data is unchanged.
 * 
 * @author github.com/tojo
 */
public interface SignatureStrategy {

	/**
	 * Calculates a signature for the given session data and returns the session
	 * data prefixed with the signature.
	 * 
	 * @param sessionData
	 * @return the session data with the calculated signature as prefix
	 * @throws InvalidInputFormatException
	 *             if the sessionData is null or empty
	 */
	byte[] sign(byte[] sessionData);

	/**
	 * Validates the session data. For this use case the method extracts the
	 * signature, which is stored as prefix in the session data, and validates
	 * the session data.
	 * 
	 * @param signedSessionData
	 *            the signed session data
	 * @return the unsigned session data if the signature validation was
	 *         successful
	 * @throws SignatureException
	 *             if the signature is invalid
	 * @throws InvalidInputFormatException
	 *             if the sessionData or signature is null, empty or too short
	 */
	byte[] validate(byte[] signedSessionData)
			throws SignatureException;
}
