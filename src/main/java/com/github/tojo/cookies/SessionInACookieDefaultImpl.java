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
package com.github.tojo.cookies;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

/**
 * Default implementation of {@link SessionInACookie}, {@link PayloadCipher},
 * {@link PayloadSigner} and {@link PayloadDecoder}.
 * 
 * @author github.com/tojo
 */
class SessionInACookieDefaultImpl extends SessionInACookie {

	public static final int SIGNATURE_LENGTH = 32;

	private static final String UTF_8 = "UTF-8";

	private static final String HMAC_SHA1 = "HmacSHA256";

	// TODO: externalize into config
	private static final String SECRET_KEY_BASE = "C4/ePwd3fA@(v9;4V=k>2G3s3(?742JZ=tB;r([2H:@i%84jdJ9kF?2[D)QRENoc9/&Xyb.MYu";

	private static final String AES = "AES";
	private static final String SHA_256 = "SHA-256";
	private static final String AES_ECB_PKCS5PADDING = "AES/ECB/PKCS5PADDING";

	@Override
	public byte[] encryptSignAndEncode(byte[] rawPayload) {
		assertNotNullAndEmpty(rawPayload);

		// 1. encrypt
		byte[] encryptedPayload = encipher(rawPayload);

		// 2. sign
		byte[] signedPayload = signAndPrefix(encryptedPayload);

		// 3. decode
		byte[] base64EncodedPayload = encodeBase64(signedPayload);

		// return the encrypted, signed and base64 encoded payload
		return base64EncodedPayload;
	}

	@Override
	public byte[] decodeDecryptAndVerifySignature(
			byte[] decodedEncryptedAndSignedPayload)
			throws InvalidSignatureOrTamperedPayloadException {
		assertMinLength(decodedEncryptedAndSignedPayload, SIGNATURE_LENGTH + 1);

		// 1. decode
		byte[] encryptedAndSignedPayload = decodeBase64(decodedEncryptedAndSignedPayload);

		// 2. validate signature
		byte[] encryptedPayload = validateSignature(encryptedAndSignedPayload);

		// 3. encrypt
		byte[] rawPayload = decipher(encryptedPayload);

		// return the decoded, decrypted and validated raw payload
		return rawPayload;
	}

	@Override
	public byte[] encipher(byte[] rawPayload) {
		assertNotNullAndEmpty(rawPayload);
		return encryptOrDecryptPayload(rawPayload, Cipher.ENCRYPT_MODE);
	}

	@Override
	public byte[] decipher(byte[] encryptedPayload) {
		assertNotNullAndEmpty(encryptedPayload);
		return encryptOrDecryptPayload(encryptedPayload, Cipher.DECRYPT_MODE);
	}

	@Override
	public byte[] sign(byte[] payload) {
		assertNotNullAndEmpty(payload);

		byte[] signature = null;
		try {
			Key key = buildKey(SECRET_KEY_BASE.getBytes(UTF_8), HMAC_SHA1);
			Mac mac = Mac.getInstance(HMAC_SHA1);
			mac.init(key);
			signature = mac.doFinal(payload);
		} catch (NoSuchAlgorithmException | UnsupportedEncodingException
				| InvalidKeyException e) {
			throw new RuntimeException(e);
		}
		return signature;
	}

	@Override
	public byte[] signAndPrefix(byte[] payload) {
		assertNotNullAndEmpty(payload);

		byte[] signature = sign(payload);
		byte[] signatureAndPayload = new byte[signature.length + payload.length];
		System.arraycopy(signature, 0, signatureAndPayload, 0, signature.length);
		System.arraycopy(payload, 0, signatureAndPayload, signature.length,
				payload.length);
		return signatureAndPayload;
	}

	@Override
	public byte[] validateSignature(byte[] signatureAndPayload)
			throws InvalidSignatureOrTamperedPayloadException {
		assertMinLength(signatureAndPayload, SIGNATURE_LENGTH + 1);

		byte[] payload = new byte[signatureAndPayload.length - SIGNATURE_LENGTH];
		byte[] signature = new byte[SIGNATURE_LENGTH];
		System.arraycopy(signatureAndPayload, SIGNATURE_LENGTH, payload, 0,
				signatureAndPayload.length - SIGNATURE_LENGTH);
		System.arraycopy(signatureAndPayload, 0, signature, 0, SIGNATURE_LENGTH);
		validateSignature(payload, signature);
		return payload;
	}

	@Override
	public void validateSignature(byte[] payload, byte[] signature)
			throws InvalidSignatureOrTamperedPayloadException {
		assertNotNullAndEmpty(payload);
		assertMinLength(signature, SIGNATURE_LENGTH);

		if (SIGNATURE_LENGTH != signature.length) {
			throw new InvalidSignatureOrTamperedPayloadException();
		}
		byte[] newSignature = sign(payload);
		if (!Arrays.equals(newSignature, signature)) {
			throw new InvalidSignatureOrTamperedPayloadException();
		}
	}

	@Override
	public byte[] encodeBase64(byte[] rawPayload) {
		assertNotNullAndEmpty(rawPayload);
		return Base64.encodeBase64(rawPayload);
	}

	@Override
	public byte[] decodeBase64(byte[] base64EncodedPayload) {
		assertNotNullAndEmpty(base64EncodedPayload);
		return Base64.decodeBase64(base64EncodedPayload);
	}

	// /////////////////////////////////////////////////
	// private methods
	// /////////////////////////////////////////////////

	private Key buildKey(byte[] password, String algorithmus)
			throws NoSuchAlgorithmException, UnsupportedEncodingException {
		assertNotNullAndEmpty(password);

		MessageDigest digester = MessageDigest.getInstance(SHA_256);
		digester.update(password);
		byte[] key = digester.digest();
		SecretKeySpec spec = new SecretKeySpec(key, algorithmus);
		return spec;
	}

	private byte[] encryptOrDecryptPayload(byte[] inputPayload, int mode) {
		assertNotNullAndEmpty(inputPayload);
		assertAllowedCipherMode(mode);

		byte[] outputPayload = null;
		try {
			Cipher cipher = Cipher.getInstance(AES_ECB_PKCS5PADDING);
			Key secretKey = buildKey(SECRET_KEY_BASE.getBytes(UTF_8), AES);
			cipher.init(mode, secretKey);
			outputPayload = cipher.doFinal(inputPayload);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException
				| UnsupportedEncodingException | InvalidKeyException
				| IllegalBlockSizeException | BadPaddingException e) {
			new RuntimeException(e);
		}
		return outputPayload;
	}

	private void assertAllowedCipherMode(int mode) {
		if (mode != Cipher.ENCRYPT_MODE && mode != Cipher.DECRYPT_MODE)
			throw new IllegalArgumentException(
					"Wrong cipher mode! Only Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE are supported.");
	}

	private void assertNotNullAndEmpty(byte[] input) {
		if (input == null || input.length == 0)
			throw new IllegalArgumentException("Input byte[] is null or empty!");
	}

	private void assertMinLength(byte[] input, int minLength) {
		assertNotNullAndEmpty(input);
		if (minLength > input.length)
			throw new IllegalArgumentException(
					"Input byte[] is to short! The length must be at least "
							+ minLength);
	}
}