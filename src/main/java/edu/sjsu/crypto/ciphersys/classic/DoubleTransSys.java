package edu.sjsu.crypto.ciphersys.classic;

import edu.sjsu.yazdankhah.crypto.util.abstracts.DoubleTransAbs;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.ConversionUtil;
import edu.sjsu.yazdankhah.crypto.util.matrixdatatypes.CharMatrix;

/**
 * Double Transposition cipher system.
 * @author Yan Chen
 * 
 * Customer: Sida Zhong
 */
public class DoubleTransSys extends DoubleTransAbs {
	
	/** Rows permutation */
	private int[] row;
	
	/** Columns permutation */
	private int[] col;
		
	/**
	 * Instantiates a new Double Transposition cipher system.
	 *
	 * @param rowPerm the rows permutation
	 * @param colPerm the columns permutation
	 */
	public DoubleTransSys(int[] rowPerm, int[] colPerm) {
		this.row = rowPerm;
		this.col = colPerm;
	}

	/**
	 * Decrypt the ciphertext.
	 *
	 * @param ciphertext
	 * @return the plaintext
	 */
	@Override
	public String decrypt(String ciphertext) {
		ciphertext = ciphertext.toLowerCase();
		CharMatrix[] plain = ConversionUtil.textToCharMatrixArr(row.length, col.length, ciphertext);
		for(int i = 0; i < plain.length; i++) {
			plain[i].inversePermuteColsM(col);
			plain[i].inversePermuteRowsM(row);
		}	
		
		return ConversionUtil.charMatrixArrToText(plain).trim();
	}

	/**
	 * Encrypt the plaintext.
	 *
	 * @param plaintext
	 * @return the ciphertext
	 */
	@Override
	public String encrypt(String plaintext) {
		plaintext = plaintext.toUpperCase();
		CharMatrix[] cipher = ConversionUtil.textToCharMatrixArr(row.length, col.length, plaintext);
		
		for(int i = 0; i < cipher.length; i++) {
			cipher[i].permuteRowsM(row);
			cipher[i].permuteColsM(col);
		}
		
		return ConversionUtil.charMatrixArrToText(cipher);
	}

}
