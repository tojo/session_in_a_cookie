package com.github.tojo.cookies;

/**
 * TODO
 */
public interface PayloadCipher {

	/**
	 * TODO
	 * 
	 * @param rawPayload
	 * @return
	 */
	byte[] encipher(byte[] rawPayload);
	
	/**
	 * TODO
	 * 
	 * @param encryptedPayload
	 * @return
	 */
	byte[] decipher(byte[] encryptedPayload);
}
