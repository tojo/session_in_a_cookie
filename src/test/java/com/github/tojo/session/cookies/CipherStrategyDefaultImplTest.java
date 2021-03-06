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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.Before;
import org.junit.Test;

public class CipherStrategyDefaultImplTest extends SessionInACookieBaseTest {

	CipherStrategyDefaultImpl sut;
	CipherStrategyDefaultImpl sut2;

	@Before
	public void setUp() throws Exception {
		sut = new CipherStrategyDefaultImpl(secret);
		sut2 = new CipherStrategyDefaultImpl(secret);
	}

	@Test
	public void testCipher() throws Exception {
		byte[] encryptedSessionData = sut
				.encipher(sampleSessionDataLoremIpsumAsBytes);
		assertNotNull(encryptedSessionData);
	}

	@Test
	public void testCipherAndDecipherSessionData() throws Exception {
		byte[] encryptedSessionData = sut
				.encipher(sampleSessionDataLoremIpsumAsBytes);
		byte[] sessionData = sut.decipher(encryptedSessionData);
		assertNotNull(sessionData);
		assertEquals(new String(sampleSessionDataLoremIpsumAsBytes, "UTF-8"),
				new String(sessionData, "UTF-8"));
	}

	@Test
	public void testMultiInstance() throws Exception {
		byte[] encryptedSessionData = sut
				.encipher(sampleSessionDataLoremIpsumAsBytes);
		byte[] encryptedSessionData2 = sut2
				.encipher(sampleSessionDataLoremIpsumAsBytes);
		byte[] sessionData = sut.decipher(encryptedSessionData2);
		byte[] sessionData2 = sut2.decipher(encryptedSessionData);
		assertEquals(new String(sampleSessionDataLoremIpsumAsBytes, "UTF-8"),
				new String(sessionData, "UTF-8"));
		assertEquals(new String(sampleSessionDataLoremIpsumAsBytes, "UTF-8"),
				new String(sessionData2, "UTF-8"));
	}

}
