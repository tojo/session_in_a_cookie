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
		byte[] signatureLoremIpsum = sut.sign(sampleSessionDataLoremIpsumAsBytes);
		byte[] signatureFooBar = sut.sign(sampleSessionDataFooBarAsBytes);
		assertEquals(SIGNATURE_LENGTH, signatureLoremIpsum.length);
		assertEquals(SIGNATURE_LENGTH, signatureFooBar.length);
		assertNotEquals(new String(signatureLoremIpsum, "UTF-8"), new String(
				signatureFooBar, "UTF-8"));
	}

	@Test
	public void testSignAndPrefixSessionData() throws Exception {
		byte[] signatureLoremIpsum = sut.sign(sampleSessionDataLoremIpsumAsBytes);
		byte[] signedSessionData = sut
				.signAndPrefix(sampleSessionDataLoremIpsumAsBytes);
		sut.validateSignature(sampleSessionDataLoremIpsumAsBytes,
				signatureLoremIpsum);
		sut.validateSignature(signedSessionData);

		// extract the session data and check it
		byte[] sessionData = new byte[signedSessionData.length - SIGNATURE_LENGTH];
		System.arraycopy(signedSessionData, SIGNATURE_LENGTH, sessionData, 0,
				signedSessionData.length - SIGNATURE_LENGTH);
		assertTrue(Arrays.equals(sampleSessionDataLoremIpsumAsBytes, sessionData));
	}

	@Test
	public void testValidateSignature() throws Exception {
		byte[] signatureLoremIpsum = sut.sign(sampleSessionDataLoremIpsumAsBytes);
		byte[] signatureFooBar = sut.sign(sampleSessionDataFooBarAsBytes);
		sut.validateSignature(sampleSessionDataLoremIpsumAsBytes,
				signatureLoremIpsum);
		sut.validateSignature(sampleSessionDataFooBarAsBytes, signatureFooBar);

		byte[] signedSessionDataLoremIpsum = sut
				.signAndPrefix(sampleSessionDataLoremIpsumAsBytes);
		byte[] sessionData = sut.validateSignature(signedSessionDataLoremIpsum);
		assertTrue(Arrays.equals(sampleSessionDataLoremIpsumAsBytes, sessionData));
	}

	@Test(expected = SignatureException.class)
	public void testValidateInvalidSignature() throws Exception {
		byte[] signatureLoremIpsum = sut.sign(sampleSessionDataLoremIpsumAsBytes);
		sut.validateSignature(sampleSessionDataFooBarAsBytes, signatureLoremIpsum);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testValidateEmptySignature() throws Exception {
		sut.validateSignature(null);
	}
}