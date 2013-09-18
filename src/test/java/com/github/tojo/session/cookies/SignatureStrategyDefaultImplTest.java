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

import static com.github.tojo.session.cookies.SignatureStrategyDefaultImpl.SIGNATURE_LENGTH;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.apache.commons.lang.ArrayUtils;
import org.junit.Before;
import org.junit.Test;

public class SignatureStrategyDefaultImplTest extends SessionInACookieBaseTest {

	private SignatureStrategyDefaultImpl sut;

	@Before
	public void setUp() throws Exception {
		sut = new SignatureStrategyDefaultImpl(secret);
	}

	@Test
	public void testSignSessionData() throws Exception {
		byte[] signedLoremIpsum = sut.sign(sampleSessionDataLoremIpsumAsBytes);
		byte[] signedFooBar = sut.sign(sampleSessionDataFooBarAsBytes);
		assertEquals(623, signedLoremIpsum.length);
		assertEquals(40, signedFooBar.length);
	}

	@Test
	public void testSignAndPrefixSessionData() throws Exception {
		byte[] signedsampleSessionDataLoremIpsumAsBytes = sut
				.sign(sampleSessionDataLoremIpsumAsBytes);
		byte[] signedSessionData = sut.sign(sampleSessionDataLoremIpsumAsBytes);
		sut.validate(signedsampleSessionDataLoremIpsumAsBytes);
		sut.validate(signedSessionData);

		// extract the session data and check it
		byte[] sessionData = ArrayUtils.subarray(signedSessionData,
				SIGNATURE_LENGTH, signedSessionData.length);
		assertTrue(Arrays.equals(sampleSessionDataLoremIpsumAsBytes,
				sessionData));
	}

	@Test
	public void testValidateSignature() throws Exception {
		byte[] signedLoremIpsum = sut.sign(sampleSessionDataLoremIpsumAsBytes);
		byte[] signedFooBar = sut.sign(sampleSessionDataFooBarAsBytes);
		sut.validate(signedLoremIpsum);
		sut.validate(signedFooBar);
	}

	@Test(expected = SignatureException.class)
	public void testValidateInvalidSignature() throws Exception {
		byte[] signedLoremIpsum = sut.sign(sampleSessionDataLoremIpsumAsBytes);
		signedLoremIpsum[0] = 0;
		sut.validate(signedLoremIpsum);
	}
}