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

import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.Before;
import org.junit.Test;

public class SessionInACookieDefaultImplTest extends SessionInACookieBaseTest {

	private SessionInACookieDefaultImpl sut;

	@Before
	public void setUp() throws Exception {
		sut = (SessionInACookieDefaultImpl) SessionInACookie
				.getDefaultInstance(secret, iv);
	}

	@Test
	public void testEncryptAndSignRoundtrip() throws CipherStrategyException,
			Exception {
		byte[] cookieValue = sut
				.encryptSignAndEncode(sampleSessionDataLoremIpsumAsBytes);
		byte[] sessionData = sut.decodeDecryptAndVerifySignature(cookieValue);
		assertTrue(Arrays.equals(sampleSessionDataLoremIpsumAsBytes,
				sessionData));
	}

	@Test(expected = InvalidInputFormatException.class)
	public void testEncryptSignAndEncodeWithNull()
			throws CipherStrategyException {
		sut.encryptSignAndEncode(null);
	}

	@Test
	public void testNonce() throws CipherStrategyException {
		String cookieValue1 = sut.encode(sampleSessionDataFooBarAsBytes);
		String cookieValue2 = sut.encode(sampleSessionDataFooBarAsBytes);
		assertNotEquals(cookieValue1, cookieValue2);
	}

	@Test
	public void testRoundTrip() throws CipherStrategyException,
			TimeoutException, SignatureException, BlacklistException {
		String cookieValue = sut.encode(sampleSessionDataFooBarAsBytes);
		byte[] sessionData = sut.decode(cookieValue);
		assertTrue(Arrays.equals(sampleSessionDataFooBarAsBytes, sessionData));
	}
}