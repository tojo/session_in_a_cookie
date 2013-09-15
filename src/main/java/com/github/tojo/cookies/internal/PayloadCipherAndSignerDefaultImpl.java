/**
 * TODO
 */
package com.github.tojo.cookies.internal;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import com.github.tojo.cookies.InvalidSignatureOrTamperedPayloadException;
import com.github.tojo.cookies.PayloadCipher;
import com.github.tojo.cookies.PayloadSigner;

/**
 * TODO
 * 
 * @author tjoch
 */
public class PayloadCipherAndSignerDefaultImpl implements PayloadCipher,
		PayloadSigner {

	private static final String HMAC_SHA1 = "HmacSHA1";

	// TODO: externalize into config
	private static final String SECRET_KEY_BASE = "C4/ePwd3fA@(v9;4V=k>2G3s3(?742JZ=tB;r([2H:@i%84jdJ9kF?2[D)QRENoc9/&Xyb.MYu";

	private static final String AES = "AES";
	private static final String SHA_256 = "SHA-256";
	private static final String AES_ECB_PKCS5PADDING = "AES/ECB/PKCS5PADDING";

	/**
	 * @see com.github.tojo.cookies.PayloadCipher#encipher(byte[])
	 */
	public byte[] encipher(byte[] rawPayload) {
		return encryptOrDecryptPayload(rawPayload, Cipher.ENCRYPT_MODE);
	}

	/**
	 * @see com.github.tojo.cookies.PayloadCipher#decipher(byte[])
	 */
	public byte[] decipher(byte[] encryptedPayload) {
		return encryptOrDecryptPayload(encryptedPayload, Cipher.DECRYPT_MODE);
	}

	/**
	 * @see com.github.tojo.cookies.PayloadCipher#sign(byte[])
	 */
	public byte[] sign(byte[] payload) {
		byte[] signature = null;
		try {
			Key key = buildKey(SECRET_KEY_BASE.getBytes("UTF-8"), HMAC_SHA1);
			Mac mac = Mac.getInstance(HMAC_SHA1);
			mac.init(key);
			signature = mac.doFinal(payload);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return signature;
	}

	public void validateSignature(byte[] signatureAndPayload)
			throws InvalidSignatureOrTamperedPayloadException {
		byte[] payload = new byte[signatureAndPayload.length - 20];
		byte[] signature = new byte[20];
		System.arraycopy(signatureAndPayload, 20, payload, 0,
				signatureAndPayload.length - 20);
		System.arraycopy(signatureAndPayload, 0, signature, 0, 20);

		validateSignature(payload, signature);
	}

	/**
	 * @see com.github.tojo.cookies.PayloadCipher#validateSignature(byte[],
	 *      byte[])
	 */
	public void validateSignature(byte[] payload, byte[] signature)
			throws InvalidSignatureOrTamperedPayloadException {
		if (signature == null || signature.length != 20) {
			throw new InvalidSignatureOrTamperedPayloadException();
		}
		byte[] newSignature = sign(payload);
		try {
			if (!new String(newSignature, "UTF-8").equals(new String(signature,
					"UTF-8"))) {
				throw new InvalidSignatureOrTamperedPayloadException();
			}
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	// /////////////////////////////////////////////////
	// private methods
	// /////////////////////////////////////////////////

	private Key buildKey(byte[] password, String algorithmus)
			throws NoSuchAlgorithmException, UnsupportedEncodingException {
		MessageDigest digester = MessageDigest.getInstance(SHA_256);
		digester.update(password);
		byte[] key = digester.digest();
		SecretKeySpec spec = new SecretKeySpec(key, algorithmus);
		return spec;
	}

	private byte[] encryptOrDecryptPayload(byte[] inputPayload, int mode) {
		byte[] outputPayload = null;
		try {
			Cipher cipher = Cipher.getInstance(AES_ECB_PKCS5PADDING);
			Key secretKey = buildKey(SECRET_KEY_BASE.getBytes("UTF-8"), AES);
			cipher.init(mode, secretKey);
			outputPayload = cipher.doFinal(inputPayload);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return outputPayload;
	}
}
