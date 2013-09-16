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
 * Methods to encode payload to and decode payload from base64.
 * 
 * @author github.com/tjoch
 */
public interface PayloadDecoder {

	/**
	 * This method encodes the given payload in the base64 format.
	 * 
	 * @param rawPayload
	 * @return The encoded payload
	 * @throws IllegalArgumentException
	 *             if the rawPayload is null or empty
	 */
	byte[] encodeBase64(byte[] rawPayload);

	/**
	 * This method decodes the given payload from the base64 format.
	 * 
	 * @param base64EncodedPayload
	 * @return The decoded payload.
	 * @throws IllegalArgumentException
	 *             if the base64EncodedPayload is null or empty
	 */
	byte[] decodeBase64(byte[] base64EncodedPayload);

}