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
 * This Exception is thrown if an error occurs during encrypting the session
 * data or decrypting the cookie value.
 * 
 * @author github.com/tojo
 */
public class CipherStrategyException extends Exception {

	private static final long serialVersionUID = 1L;

	/**
	 * Constructs a {@code CipherStrategyException} with no detail message.
	 */
	public CipherStrategyException() {
		super();
	}

	/**
	 * Constructs a {@code CipherStrategyException} with the specified detail
	 * message.
	 * 
	 * @param s
	 *            the detail message.
	 */
	public CipherStrategyException(String s) {
		super(s);
	}

	/**
	 * Constructs a {@code CipherStrategyException} with the specified detail
	 * message and cause.
	 * 
	 * @param s
	 *            the detail message
	 * @param cause
	 *            the cause
	 */
	public CipherStrategyException(String message, Throwable cause) {
		super(message, cause);
	}
}