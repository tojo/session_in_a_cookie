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
 * Methods to add sessions to a blacklist and check if it is blacklisted. The
 * check method signals through a {@link BlacklistException} that the session is
 * blacklisted.
 * 
 * @author github.com/tojo
 */
public interface BlacklistStrategy {

	/**
	 * Add a session to the blacklist.
	 * 
	 * @param cookieValue
	 *            the session / cookie value to blacklist.
	 */
	void add(String cookieValue);

	/**
	 * Check if a session / cookie value is blacklisted. If yes this method
	 * signals through a {@link BlacklistException} that the session is
	 * blacklisted.
	 * 
	 * @param cookieValue
	 *            the session / cookie value to blacklist.
	 * @throws BlacklistException
	 *             if the session is blacklisted.
	 */
	void check(String cookieValue) throws BlacklistException;
}
