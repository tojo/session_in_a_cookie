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
interface SignatureStrategy {

	/**
	 * Calculates a signature for the given session data.
	 * 
	 * @param sessionData
	 * @return the calculated signature for the given session data.
	 * @throws InvalidInputFormatException
	 *             if the sessionData is null or empty
	 */
	byte[] sign(byte[] sessionData);

	/**
	 * Validates the session data with the given signature.
	 * 
	 * @param sessionData
	 *            the signed session data
	 * @param signature
	 *            the signature
	 * @throws SignatureException
	 *             if the signature is invalid
	 * @throws InvalidInputFormatException
	 *             if the sessionData or signature is null, empty or too short
	 */
	void validateSignature(byte[] sessionData, byte[] signature)
			throws SignatureException;

	/**
	 * Getter for the strategy specific fixed length of created signatures.
	 * 
	 * @return the fixed length of a signature
	 */
	int getSignatureLength();
}
