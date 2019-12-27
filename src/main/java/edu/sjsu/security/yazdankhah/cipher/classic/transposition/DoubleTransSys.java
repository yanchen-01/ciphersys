package edu.sjsu.security.yazdankhah.cipher.classic.transposition;

import edu.sjsu.security.abstracts.CipherSysInt;
import edu.sjsu.security.ciphersysdatatypes.DoubleTransKey;
import edu.sjsu.security.cipherutils.ConversionUtil;
import edu.sjsu.security.matrixdatatypes.CharMatrix;
import lombok.extern.slf4j.Slf4j;


/**
 * Simulates double transposition cipher system.
 * 
 * @author ahmad
 */

@Slf4j
public class DoubleTransSys implements CipherSysInt {
  
  private DoubleTransKey k;
  private int row, col;
  
  
  public DoubleTransSys(DoubleTransKey k) {
    this.k = k;
    row = k.getRow();
    col = k.getCol();
  }
  
  
  /**
   * Encrypts the given plaintext and returns the ciphertext as string.
   * 
   * @param plaintext the given plaintext
   * @return encrypted text as string
   */
  @Override
  public String encrypt(String plaintext) {
    
    CharMatrix[] plaintextBlockArr = ConversionUtil.textToCharMatrixArr(row, col, plaintext);
    CharMatrix[] ciphertextBlockArr = new CharMatrix[plaintextBlockArr.length];
    
    int index = 0;
    for (CharMatrix block : plaintextBlockArr) {
      ciphertextBlockArr[index++] = encryptOneBlcok(block);
    }
    
    return ConversionUtil.charMatrixArrToText(ciphertextBlockArr).toUpperCase();
  }
  
  
  private CharMatrix encryptOneBlcok(CharMatrix block) {
    block = block.rowPermutation(k.getRowPermutation());
    block = block.colPermutation(k.getColPermutation());
    
    return block;
  }
  
  
  private CharMatrix decryptOneBlcok(CharMatrix block) {
    block = block.reverseColPermutation(k.getColPermutation());
    block = block.reverseRowPermutation(k.getRowPermutation());
    
    return block;
  }
  
  
  @Override
  public String decrypt(String ciphertext) {
    
    CharMatrix[] ciphertextBlockArr = ConversionUtil.textToCharMatrixArr(row, col, ciphertext);
    CharMatrix[] plaintextBlockArr = new CharMatrix[ciphertextBlockArr.length];
    
    int index = 0;
    for (CharMatrix block : ciphertextBlockArr) {
      plaintextBlockArr[index++] = decryptOneBlcok(block);
    }
    
    return ConversionUtil.charMatrixArrToText(plaintextBlockArr).toLowerCase().trim();
  }
  
  
  @Override
  public void printKey() {
    log.info("key = [" + k.toString() + "]");
    
  }
  
}
