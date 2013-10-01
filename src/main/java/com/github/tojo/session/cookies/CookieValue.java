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
 * Value object for the session-in-a-cookie cookie value / payload.
 * 
 * @author github.com/tojo
 */
public class CookieValue implements ValueObject {

	private final String cookieValue;

	/**
	 * Constructor
	 * 
	 * @param value
	 *            The value of the session-in-a-cookie cookie
	 */
	public CookieValue(String cookieValue) {
		this.cookieValue = cookieValue;
	}

	/**
	 * Constructor
	 * 
	 * @param value
	 *            The value of the session-in-a-cookie cookie
	 * @throws UnsupportedEncodingException
	 */
	public CookieValue(byte[] cookieValue) {
		try {
			this.cookieValue = new String(cookieValue, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new InitializationException(e);
		}
	}

	/**
	 * @return the value of the session-in-a-cookie cookie
	 */
	@Override
	public String asString() {
		return cookieValue;
	}

	/**
	 * @return the value of the session-in-a-cookie cookie encoded with UTF-8 as
	 *         byte array.
	 */
	@Override
	public byte[] asBytes() {
		try {
			return cookieValue.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new InitializationException(e);
		}
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((cookieValue == null) ? 0 : cookieValue.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		CookieValue other = (CookieValue) obj;
		if (cookieValue == null) {
			if (other.cookieValue != null)
				return false;
		} else if (!cookieValue.equals(other.cookieValue))
			return false;
		return true;
	}
}