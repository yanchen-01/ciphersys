package edu.sjsu.security.yazdankhah.cipher.classic.shift;

import edu.sjsu.security.abstracts.SimpleSubAbs;
import lombok.extern.slf4j.Slf4j;


/**
 * Simulates Simple Substitution Cipher System.
 * 
 * @author ahmad
 *
 */

@Slf4j
public class SimpleSubSys extends SimpleSubAbs {
  
  private int k;
  
  
  public SimpleSubSys(int key) {
    this.k = key;
  }
  
  
  private char encryptOneUnit(char c) {
    
    if (!Character.isAlphabetic(c)) return c;
    
    int p = SIMPLE_SUB_CHAR_TO_INT_TABLE.get(c);
    p = (p + k) % ENGLISH_ALPHABET_SIZE_CHARS;
    return SIMPLE_SUB_INT_TO_CHAR_TABLE.get(p);
  }
  
  
  private char decryptOneUnit(char c) {
    if (!Character.isAlphabetic(c)) return c;
    
    int p = SIMPLE_SUB_CHAR_TO_INT_TABLE.get(c);
    p = (p - k) % ENGLISH_ALPHABET_SIZE_CHARS;
    if (p < 0) p += ENGLISH_ALPHABET_SIZE_CHARS;
    return SIMPLE_SUB_INT_TO_CHAR_TABLE.get(p);
  }
  
  
  @Override
  public String encrypt(String plaintext) {
    
    plaintext = plaintext.toLowerCase();
    StringBuilder sb = new StringBuilder();
    
    for (char c : plaintext.toCharArray()) {
      sb.append(encryptOneUnit(c));
    }
    
    return sb.toString().toUpperCase();
  }
  
  
  @Override
  public String decrypt(String ciphertext) {
    
    ciphertext = ciphertext.toLowerCase();
    StringBuilder sb = new StringBuilder();
    
    for (char c : ciphertext.toCharArray()) {
      sb.append(decryptOneUnit(c));
    }
    
    return sb.toString();
  }


  @Override
  public void printKey() {
    log.info("key = [" + this.k + "]");
    
  }
  
}
