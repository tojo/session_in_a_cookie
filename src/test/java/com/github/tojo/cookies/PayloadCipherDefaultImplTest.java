package com.github.tojo.cookies;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.BeforeClass;
import org.junit.Test;

import com.github.tojo.cookies.InvalidSignatureOrTamperedPayloadException;

public class PayloadCipherDefaultImplTest {

	private static final int SIGNATURE_LENGTH = 32;
	static SessionInACookie sut;
	static String samplePayloadLoremIpsum;
	static byte[] samplePayloadLoremIpsumAsBytes;
	static String samplePayloadFooBar;
	static byte[] samplePayloadFooBarAsBytes;

	@BeforeClass
	public static void setup() throws Exception {
		sut = SessionInACookie.getDefaultInstance();
		samplePayloadLoremIpsum = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet.";
		samplePayloadLoremIpsumAsBytes = samplePayloadLoremIpsum
				.getBytes("UTF-8");
		samplePayloadFooBar = "Foo bar!";
		samplePayloadFooBarAsBytes = samplePayloadFooBar.getBytes("UTF-8");
	}

	@Test
	public void testCipherPayload() throws Exception {
		byte[] encryptedPayload = sut.encipher(samplePayloadLoremIpsumAsBytes);
		assertNotNull(encryptedPayload);
	}

	@Test
	public void testCipherAndDecipherPayload() throws Exception {
		byte[] encryptedPayload = sut.encipher(samplePayloadLoremIpsumAsBytes);
		byte[] rawPayload = sut.decipher(encryptedPayload);
		assertNotNull(rawPayload);
		assertEquals(new String(samplePayloadLoremIpsumAsBytes, "UTF-8"),
				new String(rawPayload, "UTF-8"));
	}

	@Test
	public void testSignPayload() throws Exception {
		byte[] signatureLoremIpsum = sut.sign(samplePayloadLoremIpsumAsBytes);
		byte[] signatureFooBar = sut.sign(samplePayloadFooBarAsBytes);
		assertEquals(SIGNATURE_LENGTH, signatureLoremIpsum.length);
		assertEquals(SIGNATURE_LENGTH, signatureFooBar.length);
		assertNotEquals(new String(signatureLoremIpsum, "UTF-8"), new String(
				signatureFooBar, "UTF-8"));
	}

	@Test
	public void testSignAndPrefixPayload() throws Exception {
		byte[] signatureLoremIpsum = sut.sign(samplePayloadLoremIpsumAsBytes);
		byte[] signatureAndPayload = sut
				.signAndPrefix(samplePayloadLoremIpsumAsBytes);
		sut.validateSignature(samplePayloadLoremIpsumAsBytes,
				signatureLoremIpsum);
		sut.validateSignature(signatureAndPayload);

		// extract the payload and check it
		byte[] payload = new byte[signatureAndPayload.length - SIGNATURE_LENGTH];
		System.arraycopy(signatureAndPayload, SIGNATURE_LENGTH, payload, 0,
				signatureAndPayload.length - SIGNATURE_LENGTH);
		assertTrue(Arrays.equals(samplePayloadLoremIpsumAsBytes, payload));
	}

	@Test
	public void testValidateSignature() throws Exception {
		byte[] signatureLoremIpsum = sut.sign(samplePayloadLoremIpsumAsBytes);
		byte[] signatureFooBar = sut.sign(samplePayloadFooBarAsBytes);
		sut.validateSignature(samplePayloadLoremIpsumAsBytes,
				signatureLoremIpsum);
		sut.validateSignature(samplePayloadFooBarAsBytes, signatureFooBar);

		byte[] signatureAndPayloadLoremIpsum = sut
				.signAndPrefix(samplePayloadLoremIpsumAsBytes);
		byte[] payload = sut.validateSignature(signatureAndPayloadLoremIpsum);
		assertTrue(Arrays.equals(samplePayloadLoremIpsumAsBytes, payload));
	}

	@Test(expected = InvalidSignatureOrTamperedPayloadException.class)
	public void testValidateInvalidSignature() throws Exception {
		byte[] signatureLoremIpsum = sut.sign(samplePayloadLoremIpsumAsBytes);
		sut.validateSignature(samplePayloadFooBarAsBytes, signatureLoremIpsum);
	}

	@Test
	public void testIssueCookiePayloadAndDecryptAgain()
			throws InvalidSignatureOrTamperedPayloadException, Exception {
		byte[] sessionInACookiePayload = sut
				.encryptSignAndEncode(samplePayloadLoremIpsumAsBytes);
		byte[] rawPayload = sut
				.decodeDecryptAndVerifySignature(sessionInACookiePayload);
		assertTrue(Arrays.equals(samplePayloadLoremIpsumAsBytes, rawPayload));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testIssueEmptyCookiePayload() {
		sut.encryptSignAndEncode(null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testValidateEmptySignature() throws Exception {
		sut.validateSignature(null);
	}
}