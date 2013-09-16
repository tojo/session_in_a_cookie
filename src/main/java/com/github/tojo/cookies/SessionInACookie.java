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
 * Helper methods for implementing the session-in-a-cookie pattern.
 * 
 * @author github.com/tojo
 */
public abstract class SessionInACookie implements PayloadCipher, PayloadSigner,
		PayloadDecoder {

	private static SessionInACookie instance = null;

	/**
	 * Encrypts, sign and base64 encodes the payload.
	 * 
	 * @param rawPayload
	 *            the raw payload
	 * @return The encrypted, signed and base64 encoded payload.
	 * @throws IllegalArgumentException
	 *             if the rawPayload is null or empty
	 */
	abstract byte[] encryptSignAndEncode(byte[] rawPayload);

	/**
	 * Decodes from base64, validates signature and decrypt the payload.
	 * 
	 * @param encryptedAndSignedPayload
	 * @return The raw payload.
	 * @throws InvalidSignatureOrTamperedPayloadException
	 * @throws IllegalArgumentException
	 *             if the encryptedAndSignedPayload is null, empty or too short
	 */
	abstract byte[] decodeDecryptAndVerifySignature(
			byte[] encryptedAndSignedPayload)
			throws InvalidSignatureOrTamperedPayloadException;

	/**
	 * Get the default {@link SessionInACookie} implementation object.
	 * 
	 * @param secretKey
	 *            the shared secret which for en- and decryption.
	 * @return the default {@link SessionInACookie} object
	 */
	public static SessionInACookie getDefaultInstance(String secretKey) {
		if (instance == null) {
			instance = new SessionInACookieDefaultImpl(secretKey);
		}
		return instance;
	}
}