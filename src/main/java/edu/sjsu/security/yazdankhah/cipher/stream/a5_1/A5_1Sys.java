package edu.sjsu.security.yazdankhah.cipher.stream.a5_1;

import java.util.ArrayList;
import java.util.List;

import edu.sjsu.security.abstracts.A5_1Int;
import edu.sjsu.security.cipherutils.ConversionUtil;
import edu.sjsu.security.cipherutils.Function;
import edu.sjsu.security.cipherutils.StringUtil;
import edu.sjsu.security.primitivedatatypes.Bit;
import edu.sjsu.security.shiftregisters.LFSR;
import lombok.extern.slf4j.Slf4j;


/**
 * Simulates stream cipher A5/1.
 * 
 * @author ahmad
 */
@Slf4j
public final class A5_1Sys implements A5_1Int {
  
  private final List<Bit> keyStream = new ArrayList<>();
  
  private LFSR X, Y, Z;
  
  /**
   * Constructs a new object of A5_1. If the pass is not at least 8 characters, then it will be
   * padded by 0's on the right.
   * @param pass
   */
  public A5_1Sys(String pass) {
    
    pass = StringUtil.rightTruncRightPadWithZeros(pass, PASS_MIN_SIZE_CHARS);
    String binStr = ConversionUtil.textToBinStr(pass);
    
    X = LFSR.constructFromBinStr(binStr.substring(0, X_REG_SIZE_BITS), X_TAPS);
    Y = LFSR.constructFromBinStr(binStr.substring(X_REG_SIZE_BITS, X_REG_SIZE_BITS + Y_REG_SIZE_BITS), Y_TAPS);
    Z = LFSR.constructFromBinStr(binStr.substring(X_REG_SIZE_BITS + Y_REG_SIZE_BITS), Z_TAPS);
    
//    X.printAllFormat();
//    Y.printAllFormat();
//    Z.printAllFormat();
  }
  
  
  @Override
  public Bit generateKey() {
    
  //for the numbers, refer to the A5/1 algorithm
    Bit[] majArr = { X.bitAt(8), Y.bitAt(10), Z.bitAt(10) }; 
    
    Bit m = Function.maj(majArr);
    
    if (m.equal(X.bitAt(8)))  X.stepM();
    if (m.equal(Y.bitAt(10))) Y.stepM();
    if (m.equal(Z.bitAt(10))) Z.stepM();
    
    Bit kI = X.getOutput().xor(Y.getOutput()).xor(Z.getOutput());
    keyStream.add(kI);
    
    return kI;
  }
  
  
  /**
   * Encrypts the given plaintext and returns the encrypted text as hex numbers.
   * 
   * @param plainText the given plaintext
   * @return the ciphertext
   */
  public String encrypt(String plainText) {
    
    Bit[] plaintextBitArr = ConversionUtil.textToBitArr(plainText);
    Bit[] ciphertextBitArr = new Bit[plaintextBitArr.length];
    
    int index = 0;
    for (Bit e : plaintextBitArr) {
      Bit kI = generateKey();
      ciphertextBitArr[index++] = e.xor(kI);
    }
    
    return ConversionUtil.bitArrToHexStr(ciphertextBitArr);
  }
  
  
  /**
   * Decrypts the given ciphertext as hex string and returns the recovered plaintext.
   * 
   * @param cipherHexStr the given ciphertext as hex string
   * @return the recovered plaintext
   */
  public String decrypt(String cipherHexStr) {
    
    String cipherBinStr = ConversionUtil.hexStrToBinStr(cipherHexStr);
    
    Bit[] ciphertextBitArr = ConversionUtil.binStrToBitArr(cipherBinStr);
    Bit[] plaintextBitArr = new Bit[ciphertextBitArr.length];
    
    int index = 0;
    for (Bit e : ciphertextBitArr) {
      Bit kI = generateKey();
      plaintextBitArr[index++] = e.xor(kI);
    }
    
    String binStr = ConversionUtil.bitArrToBinStr(plaintextBitArr);
    
    return ConversionUtil.binStrToText(binStr);
  }
  
  
  @Override
  public void printKeyStreamList(String msg) {
    log.info(keyStream.toString() + " " + msg);
  }
  
}
