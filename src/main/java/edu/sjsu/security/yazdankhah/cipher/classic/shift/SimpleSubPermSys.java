package edu.sjsu.security.yazdankhah.cipher.classic.shift;

import java.util.Map;

import edu.sjsu.security.abstracts.SimpleSubAbs;
import edu.sjsu.security.ciphersysdatatypes.SimpleSubKey;
import lombok.extern.slf4j.Slf4j;


/**
 * Simulates generalized simple substitution cipher system.
 * 
 * @author ahmad
 */

@Slf4j
public class SimpleSubPermSys extends SimpleSubAbs {
  
  private SimpleSubKey k;
  
  private Map<Character, Character> encryptionMap;
  private Map<Character, Character> decryptionMap;
  
  
  public SimpleSubPermSys(String keyStr) {
    this.k = SimpleSubKey.constructFromStr(keyStr);
    encryptionMap = this.k.constructEncryptionMap();
    decryptionMap = this.k.constructDecryptionMap();
  }
  
  
  private char encryptOneUnit(char c) {
    if (!Character.isAlphabetic(c)) return c;
    return encryptionMap.get(c);
  }
  
  
  private char decryptOneUnit(char c) {
    if (!Character.isAlphabetic(c)) return c;
    return decryptionMap.get(c);
  }
  
  
  /**
   * Encrypts the input plaintext and returns the ciphertext as uppercase string.
   * 
   * @param plaintext the input plaintext
   * @return the encrypted text as string
   */
  @Override
  public String encrypt(String plaintext) {
    
    plaintext = plaintext.toLowerCase();
    StringBuilder sb = new StringBuilder(plaintext.length());
    
    for (char c : plaintext.toCharArray()) {
      sb.append(encryptOneUnit(c));
    }
    return sb.toString();
  }
  
  
  /**
   * Decrypts the input ciphertext and returns the plaintext as lowercase string.
   * 
   * @param ciphertext the input ciphertext
   * @return the decrypted text as string
   */
  @Override
  public String decrypt(String ciphertext) {
    
    StringBuilder sb = new StringBuilder(ciphertext.length());
    
    for (char c : ciphertext.toCharArray()) {
      sb.append(decryptOneUnit(c));
    }
    return sb.toString();
  }
  
  
  @Override
  public void printKey() {
    k.printText("The Given Key");
  }
  
}
