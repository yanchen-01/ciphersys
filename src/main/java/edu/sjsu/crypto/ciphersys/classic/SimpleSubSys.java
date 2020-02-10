package edu.sjsu.crypto.ciphersys.classic;

import java.util.Map;

import edu.sjsu.yazdankhah.crypto.util.abstracts.SimpleSubAbs;
import edu.sjsu.yazdankhah.crypto.util.shiftregisters.CSR;

/**
 * Simple Substitution Cipher System that encrypt and 
 * decrypt messages based on a key.
 *
 * @author Yan Chen
 * 
 * Customer: Sida Zhong
 */
public class SimpleSubSys extends SimpleSubAbs {
	
	/** The lookup table for encryption. */
	private static Map<Character, Character> encryptionTable;
	
	/** The lookup table for decryption. */
	private static Map<Character, Character> decryptionTable;

	/**
	 * Instantiates a new Simple Substitution Cipher System.
	 *
	 * @param key number of rotation
	 */
	public SimpleSubSys(int key) {
		CSR plain = CSR.constructFromText(ENGLISH_ALPHABET_STR);
		CSR cipher = plain.rotateLeft(key);
		encryptionTable = SimpleSubAbs.makeLookupTable(plain, cipher);
		decryptionTable = SimpleSubAbs.makeLookupTable(cipher, plain);
	}

	/**
	 * Encrypt plaintext to ciphertext.
	 *
	 * @param plaintext the plaintext
	 * @return the result ciphertext
	 */
	@Override
	public String encrypt(String plaintext) {
		plaintext = plaintext.toLowerCase();
		String ciphertext = "";
		for (int i = 0; i < plaintext.length(); i++) {
			char current = plaintext.charAt(i);
			if (Character.isLetter(current))
				current = encryptionTable.get(current);
			ciphertext += current;
		}
		return ciphertext.toUpperCase();
	}

	
	/**
	 * Decrypt ciphertext to plaintext.
	 *
	 * @param ciphertext the ciphertext
	 * @return the result plaintext
	 */
	@Override
	public String decrypt(String ciphertext) {
		ciphertext = ciphertext.toLowerCase();
		String plaintext = "";
		for (int i = 0; i < ciphertext.length(); i++) {
			char current = ciphertext.charAt(i);
			if (Character.isLetter(current))
				current = decryptionTable.get(current);
			plaintext += current;
		}
		return plaintext;
	}

}
