/**
 * 
 */
package com.github.tojo.cookies;

/**
 * TODO
 * 
 * @author tjoch
 */
public interface PayloadSigner {

	/**
	 * TODO
	 * 
	 * @param payload
	 * @return
	 */
	byte[] sign(byte[] payload);

	/**
	 * TODO
	 * 
	 * @param payload
	 * @param signature
	 * @throws InvalidSignatureOrTamperedPayloadException
	 */
	void validateSignature(byte[] payload, byte[] signature)
			throws InvalidSignatureOrTamperedPayloadException;
}
