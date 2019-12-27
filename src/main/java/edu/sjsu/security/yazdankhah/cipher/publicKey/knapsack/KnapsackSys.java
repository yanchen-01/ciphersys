package edu.sjsu.security.yazdankhah.cipher.publicKey.knapsack;

import java.math.BigInteger;
import java.util.Random;

import edu.sjsu.security.abstracts.KnapsackAbs;
import edu.sjsu.security.ciphersysdatatypes.KnapsackPrivateKey;
import edu.sjsu.security.ciphersysdatatypes.KnapsackPublicKey;
import edu.sjsu.security.cipherutils.ConversionUtil;
import edu.sjsu.security.cipherutils.FileUtil;
import edu.sjsu.security.cipherutils.Function;
import edu.sjsu.security.cipherutils.StringUtil;
import edu.sjsu.security.primitivedatatypes.Bit;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.extern.slf4j.Slf4j;


/**
 * Simulates Knapsack public key cipher system.
 * 
 * @author ahmad
 */

@Slf4j
@Data
@EqualsAndHashCode(callSuper = false)
public class KnapsackSys extends KnapsackAbs {
  
  private KnapsackPrivateKey privateKey;
  private KnapsackPublicKey publicKey;
  
  
  /**
   * Constructs a new set of public and private keys by using the provided pass text.
   * 
   * @param pass the given pass text
   * @return a new object of KnapsackKey
   */
  public void constructKnapsackKeys(String pass, String name) {
    Random rnd = KnapsackAbs.getRandomGenerator(pass);
    
    BigInteger[] w = KnapsackAbs.generateSuperIncreasingKnapsack(rnd);
    
    BigInteger m = Function.generateRandomPositiveInteger(rnd); // 32-bit
    BigInteger p = Function.generateRandomPrimeBigIntegerBiggerThan(Function.sumBigIntegerArr(w), rnd);
    
    BigInteger[] wP = KnapsackAbs.convertSuperIncreasingToRegularKnapsack(w, m, p);
    
    this.publicKey = new KnapsackPublicKey(name, wP);
    this.privateKey = new KnapsackPrivateKey(w, m, p);
    
  }
  
  
  /**
   * Saves the private-key as an object at the given fully-qualified-name file.
   * 
   * @param fqn the given fully-qualified-name file name
   */
  public void savePrivateKey(String fqn) {
    FileUtil.saveObj(this.privateKey, fqn);
  }
  
  
  /**
   * Restores the private-key as an object from the given fully-qualified-name file.
   * 
   * @param fqn the given fully-qualified-name file name
   */
  public void restorePrivateKey(String fqn) {
    this.privateKey = (KnapsackPrivateKey) FileUtil.restoreObj(fqn);
  }
  
  
  /**
   * Saves the public-key as an object at the given fully-qualified-name file.
   * 
   * @param fqn the given fully-qualified-name file name
   */
  public void savePublicKey(String fqn) {
    FileUtil.saveObj(this.publicKey, fqn);
  }
  
  
  /**
   * Restores the public-key as an object from the given fully-qualified-name file.
   * 
   * @param fqn the given fully-qualified-name file name
   */
  public void restorePublicKey(String fqn) {
    this.publicKey = (KnapsackPublicKey) FileUtil.restoreObj(fqn);
  }
  
  
  /**
   * Decrypts the given ciphertext and returns the plaintext as plaintext.
   * 
   * @param ciphertext the given ciphertext
   * @param privateKey the given private-key
   * @return decrypted text as string
   */
  @Override
  public String decrypt(String ciphertext, KnapsackPrivateKey privateKey) {
    
    String[] ciphertextBlockArr = StringUtil.strToStrArr(ciphertext, KNAPSACK_CIPHER_BLOCK_SIZE_HEX);
    StringBuilder plaintextSb = new StringBuilder();
    
    BigInteger p = privateKey.getP();
    BigInteger mInv = privateKey.getM().modInverse(privateKey.getP());
    
    for (String block : ciphertextBlockArr) {
      plaintextSb.append(decryptOneBlcok(block, privateKey.getW(), mInv, p));
    }
    return plaintextSb.toString().trim();
  }
  
  
  private static String decryptOneBlcok(String block, BigInteger[] w, BigInteger mInv, BigInteger p) {
    BigInteger c = new BigInteger(block, 16);
    c = c.multiply(mInv).mod(p);
    Bit[] bitArr = solveSuperIncreasingKnapsack(w, c);
    return ConversionUtil.bitArrToText(bitArr);
  }
  
  
  private static String encryptOneBlcok(String block, BigInteger[] wp) {
    
    Bit[] bitArr = ConversionUtil.textToBitArr(block);
    BigInteger c = BigInteger.ZERO;
    
    for (int i = 0; i < bitArr.length; i++) {
      if (bitArr[i].isOne()) {
        c = c.add(wp[i]);
      }
    }
    return c.toString(16); // 16 = radix
  }
  
  
  /**
   * Encrypts the given plaintext by using the given public-key and returns the ciphertext as a
   * string of hex digits (ciphertext).
   * 
   * @param plaintext the given plaintext
   * @param publicKey the given public-key
   * @return encrypted text as a string of hex digits
   */
  @Override
  public String encrypt(String plaintext, KnapsackPublicKey publicKey) {
    
    String[] plaintextBlockArr = StringUtil.strToStrArr(plaintext, KNAPSACK_PLAIN_BLOCK_SIZE_CHAR);
    StringBuilder ciphertextSb = new StringBuilder();
    
    for (String block : plaintextBlockArr) {
      ciphertextSb.append(encryptOneBlcok(block, publicKey.getWp()));
    }
    return ciphertextSb.toString();
  }
  
  
  @Override
  public void printKey() {
//    PrintUtil.printIntArr(k, "Key");
  }
  
}
