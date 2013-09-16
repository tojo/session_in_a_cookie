package com.github.tojo.cookies;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.BeforeClass;
import org.junit.Test;

import com.github.tojo.cookies.InvalidSignatureOrTamperedPayloadException;
import com.github.tojo.cookies.SessionInACookieDefaultImpl;

public class PayloadCipherDefaultImplTest {

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
		assertEquals(20, signatureLoremIpsum.length);
		assertEquals(20, signatureFooBar.length);
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
		byte[] payload = new byte[signatureAndPayload.length - 20];
		System.arraycopy(signatureAndPayload, 20, payload, 0,
				signatureAndPayload.length - 20);
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
	public void issueCookiePayload()
			throws InvalidSignatureOrTamperedPayloadException, Exception {
		byte[] sessionInACookiePayload = sut
				.encryptSignAndEncode(samplePayloadLoremIpsumAsBytes);
		byte[] rawPayload = sut
				.decodeDecryptAndVerifySignature(sessionInACookiePayload);
		assertTrue(Arrays.equals(samplePayloadLoremIpsumAsBytes, rawPayload));
	}

	@Test
	public void decryptCookiePayload() {

	}
}