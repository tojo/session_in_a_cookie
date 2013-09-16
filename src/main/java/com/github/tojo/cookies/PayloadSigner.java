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
 * Methods to create and verify signatures. This is useful to check the data
 * integrity and make sure that the payload is unchanged.
 * 
 * @author github.com/tojo
 */
public interface PayloadSigner {

	/**
	 * Calculates a signature for the given payload.
	 * 
	 * @param payload
	 * @return The signature.
	 * @throws IllegalArgumentException
	 *             if the payload is null or empty
	 */
	byte[] sign(byte[] payload);

	/**
	 * Calculates a signature for the given payload and prefix the payload with
	 * it.
	 * 
	 * @param payload
	 * @return The signature + payload.
	 * @throws IllegalArgumentException
	 *             if the payload is null or empty
	 */
	byte[] signAndPrefix(byte[] payload);

	/**
	 * Extracts the first 20 bytes of the payload as signature and validates the
	 * payload with it.
	 * 
	 * @param signatureAndPayload
	 * @return The valid payload without the signature.
	 * @throws InvalidSignatureOrTamperedPayloadException
	 * @throws IllegalArgumentException
	 *             if the signatureAndPayload is null, empty or too short
	 */
	byte[] validateSignature(byte[] signatureAndPayload)
			throws InvalidSignatureOrTamperedPayloadException;

	/**
	 * Validates the payload with the given signature.
	 * 
	 * @param payload
	 * @param signature
	 * @throws InvalidSignatureOrTamperedPayloadException
	 * @throws IllegalArgumentException
	 *             if the payload or signature is null, empty or too short
	 */
	void validateSignature(byte[] payload, byte[] signature)
			throws InvalidSignatureOrTamperedPayloadException;
}
