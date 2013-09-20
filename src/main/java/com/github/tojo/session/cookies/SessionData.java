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

import java.io.UnsupportedEncodingException;

/**
 * Value object for the serialized session-in-a-cookie session data.
 * 
 * @author github.com/tojo
 */
public class SessionData implements ValueObject {

	private byte[] sessionData;

	/**
	 * Constructor
	 */
	public SessionData() {
	}

	/**
	 * Constructor
	 * 
	 * @param sessionData
	 *            the serialized session-in-a-cookie session data
	 */
	public SessionData(byte[] sessionData) {
		this.sessionData = sessionData;
	}

	/**
	 * @return the serialized session-in-a-cookie session data converted in a
	 *         UTF-8 string.
	 */
	@Override
	public String asString() {
		try {
			return new String(sessionData, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new InitializationError(e);
		}
	}

	/**
	 * @return the serialized session-in-a-cookie session data
	 */
	@Override
	public byte[] asBytes() {
		return sessionData;
	}
}