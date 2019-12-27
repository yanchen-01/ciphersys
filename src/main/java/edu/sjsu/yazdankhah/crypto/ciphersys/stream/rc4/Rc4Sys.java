package edu.sjsu.yazdankhah.crypto.ciphersys.stream.rc4;

import java.util.ArrayList;
import java.util.List;

import edu.sjsu.yazdankhah.crypto.util.abstracts.Rc4SysInt;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.ConversionUtil;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.GeneralUtil;
import edu.sjsu.yazdankhah.crypto.util.primitivedatatypes.UByte;
import lombok.extern.slf4j.Slf4j;

/**
 * Simulates stream cipher RC4.
 * 
 * @author ahmad
 */
@Slf4j
public class Rc4Sys implements Rc4SysInt {
  
  private final List<UByte> keyStream = new ArrayList<>();
  private UByte[] key, S, K;
  private int indexI = 0, indexJ = 0;
  
  
  public Rc4Sys(String pass) {
    
    //what is the size of pass? Put a prerequisite or check it.
    
    key = ConversionUtil.textToUByteArr(pass);
    S = new UByte[ARRAY_SIZE]; // look up array
    K = new UByte[ARRAY_SIZE]; // key content
    
    init();
  }
  
  
  /**
   * Converts the plain text to cipher text.
   * 
   * @param plainText
   * @return
   */
  public String encrypt(String plainText) {
    
    UByte[] plaintextUByteArr = ConversionUtil.textToUByteArr(plainText);
    UByte[] ciphertextUByteArr = new UByte[plaintextUByteArr.length];
    
    int index = 0;
    for (UByte e : plaintextUByteArr) {
      UByte kI = generateKey();
      ciphertextUByteArr[index++] = e.xor(kI);
    }
    
    return ConversionUtil.ubyteArrToHexStr(ciphertextUByteArr);
  }
  
  
  /**
   * Initializes the starting configuration.
   */
  private void init() {
    
    int N = key.length;
    
    // K and S initialization
    for (int i = 0; i < ARRAY_SIZE; i++) {
      S[i] = UByte.constructFromInteger(i);
      K[i] = key[i % N];
    }
    
    // initial permutation of S
    int j = 0;
    for (int i = 0; i < ARRAY_SIZE; i++) {
      j = (j + S[i].toInteger() + K[i].toInteger()) % ARRAY_SIZE;
      GeneralUtil.swapM(S, i, j);
    }
    
  }
  
  
  /**
   * Produces one byte of key stream.
   * 
   * @return
   */
  public UByte generateKey() {
    
    indexI = (indexI + 1) % ARRAY_SIZE;
    indexJ = (indexJ + S[indexI].toInteger()) % ARRAY_SIZE;
    GeneralUtil.swapM(S, indexI, indexJ);
    int t = (S[indexI].toInteger() + S[indexJ].toInteger()) % ARRAY_SIZE;
    
    keyStream.add(S[t]);
    
    return S[t];
  }
  
  
  @Override
  public String decrypt(String cipherHexStr) {
    
    String ciphertext = ConversionUtil.hexStrToText(cipherHexStr);
    
    UByte[] ciphertextUByteArr = ConversionUtil.textToUByteArr(ciphertext);
    UByte[] plaintextUByteArr = new UByte[ciphertextUByteArr.length];
    
    int index = 0;
    for (UByte e : ciphertextUByteArr) {
      UByte kI = generateKey();
      plaintextUByteArr[index++] = e.xor(kI);
    }
    
    return ConversionUtil.ubyteArrToText(plaintextUByteArr);
  }
  
  
  @Override
  public void printKeyStreamList(String msg) {
    log.info(keyStream.toString() + " " + msg);
  }
  
}
