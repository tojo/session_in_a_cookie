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
 * Methods to issue, advance and expire sessions. The advance method signals
 * through a {@link TimeoutException} that the session was expired or not
 * well-known.
 * 
 * @author github.com/tojo
 */
public interface TimeoutStrategy {

	/**
	 * Issues and initialize the timeout handling for the given session / cookie
	 * value.
	 * 
	 * @param cookieValue
	 *            the session / cookie value for which the timeout handling
	 *            infrastructure should be initialized
	 */
	void issue(String cookieValue);

	/**
	 * Advance the session timeout.
	 * 
	 * @param cookieValue
	 *            the session / cookie value which should be advanced
	 * @throws TimeoutException
	 *             if the session couldn't advanced, e.g. because it is expired
	 *             or not well-known.
	 */
	void advance(String cookieValue) throws TimeoutException;

	/**
	 * Mark a session as expired.
	 * 
	 * @param cookieValue
	 *            the session / cookie value which should be marked as expired
	 */
	void expire(String cookieValue);
}