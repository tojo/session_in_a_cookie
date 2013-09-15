package com.github.tojo.cookies.internal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.BeforeClass;
import org.junit.Test;

import com.github.tojo.cookies.InvalidSignatureOrTamperedPayloadException;

public class PayloadCipherDefaultImplTest {

	static PayloadCipherAndSignerDefaultImpl sut;
	static byte[] samplePayloadLoremIpsum;
	static byte[] samplePayloadFooBar;

	@BeforeClass
	public static void setup() throws Exception {
		sut = new PayloadCipherAndSignerDefaultImpl();
		samplePayloadLoremIpsum = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet."
				.getBytes("UTF-8");
		samplePayloadFooBar = "Foo bar!".getBytes("UTF-8");
	}

	@Test
	public void testCipherPayload() throws Exception {
		byte[] encryptedPayload = sut.encipher(samplePayloadLoremIpsum);
		assertNotNull(encryptedPayload);
	}

	@Test
	public void testCipherAndDecipherPayload() throws Exception {
		byte[] encryptedPayload = sut.encipher(samplePayloadLoremIpsum);
		byte[] rawPayload = sut.decipher(encryptedPayload);
		assertNotNull(rawPayload);
		assertEquals(new String(samplePayloadLoremIpsum, "UTF-8"), new String(
				rawPayload, "UTF-8"));
	}

	@Test
	public void testSignPayload() throws Exception {
		byte[] signatureLoremIpsum = sut.sign(samplePayloadLoremIpsum);
		byte[] signatureFooBar = sut.sign(samplePayloadFooBar);
		assertEquals(20, signatureLoremIpsum.length);
		assertEquals(20, signatureFooBar.length);
		assertNotEquals(new String(signatureLoremIpsum, "UTF-8"), new String(
				signatureFooBar, "UTF-8"));
	}

	@Test
	public void testValidateSignature() throws Exception {
		byte[] signatureLoremIpsum = sut.sign(samplePayloadLoremIpsum);
		byte[] signatureFooBar = sut.sign(samplePayloadFooBar);
		sut.validateSignature(samplePayloadLoremIpsum, signatureLoremIpsum);
		sut.validateSignature(samplePayloadFooBar, signatureFooBar);
	}

	@Test(expected = InvalidSignatureOrTamperedPayloadException.class)
	public void testValidateInvalidSignature() throws Exception {
		byte[] signatureLoremIpsum = sut.sign(samplePayloadLoremIpsum);
		sut.validateSignature(samplePayloadFooBar, signatureLoremIpsum);
	}
}