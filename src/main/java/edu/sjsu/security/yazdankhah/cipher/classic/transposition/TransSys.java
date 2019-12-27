package edu.sjsu.security.yazdankhah.cipher.classic.transposition;

import edu.sjsu.security.abstracts.CipherSysInt;
import edu.sjsu.security.cipherutils.ConversionUtil;
import edu.sjsu.security.cipherutils.PrintUtil;
import edu.sjsu.security.shiftregisters.CSR;


/**
 * Simulates transposition cipher system.
 * 
 * @author ahmad
 */

//@Slf4j
public class TransSys implements CipherSysInt {
  
  private int[] k;
  private int blockSize;
  
  
  public TransSys(int[] k) {
    this.k = k;
    this.blockSize = k.length;
  }
  
  
  /**
   * Encrypts the given plaintext and returns the ciphertext as string.
   * 
   * @param plaintext the given plaintext
   * @return encrypted text as string
   */
  @Override
  public String encrypt(String plaintext) {
    
    CSR[] plaintextBlockArr = ConversionUtil.textToCsrArr(plaintext, blockSize);
    CSR[] ciphertextBlockArr = new CSR[plaintextBlockArr.length];
    
    int index = 0;
    for (CSR block : plaintextBlockArr) {
      ciphertextBlockArr[index++] = encryptOneBlcok(block);
    }
    
    return ConversionUtil.csrArrToText(ciphertextBlockArr).toUpperCase();
  }
  
  
  private CSR encryptOneBlcok(CSR block) {
    return block.permute(k);
  }
  
  
  private CSR decryptOneBlcok(CSR block) {
    return block.inversePermute(k);
  }
  
  
  /**
   * Decrypts the given ciphertext and returns the plaintext as string.
   * 
   * @param ciphertext the given ciphertext
   * @return decrypted text as string
   */
  @Override
  public String decrypt(String ciphertext) {
    
    CSR[] ciphertextBlockArr = ConversionUtil.textToCsrArr(ciphertext, blockSize);
    CSR[] plaintextBlockArr = new CSR[ciphertextBlockArr.length];
    
    int index = 0;
    for (CSR block : ciphertextBlockArr) {
      plaintextBlockArr[index++] = decryptOneBlcok(block);
    }
    
    return ConversionUtil.csrArrToText(plaintextBlockArr).toLowerCase().trim();
    
  }
  
  
  @Override
  public void printKey() {
    PrintUtil.printIntArr(k, "Key");
  }
  
}
