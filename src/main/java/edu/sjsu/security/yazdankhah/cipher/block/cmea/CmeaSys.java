package edu.sjsu.security.yazdankhah.cipher.block.cmea;

import edu.sjsu.security.abstracts.CmeaInt;
import edu.sjsu.security.cipherutils.ConversionUtil;
import edu.sjsu.security.cipherutils.GeneralUtil;
import edu.sjsu.security.cipherutils.PrintUtil;
import edu.sjsu.security.cipherutils.StringUtil;
import edu.sjsu.security.matrixdatatypes.LookupTable;
import edu.sjsu.security.primitivedatatypes.UByte;
import edu.sjsu.security.primitivedatatypes.Word;
import lombok.extern.slf4j.Slf4j;


/**
 * Simulates block cipher CMEA.
 * 
 * @author ahmad
 */
@Slf4j
public class CmeaSys implements CmeaInt {
  
  private LookupTable lookupTable;
  private UByte[] K;
  
  
  /**
   * Constructs a new object of CmeaSys. If the pass is not at least 8 characters, then it will be
   * padded by 0's on the right.
   * 
   * @param passText the provide pass key in text
   */
  public CmeaSys(String passText) {
    
    K = ConversionUtil.textToUByteArr(passText, KEY_BLOCK_SIZE_BYTES);
    lookupTable = LookupTable.constructFromHexStr(CAVE_TABLE_SIZE, CAVE_TABLE);
    PrintUtil.printUByteArrAsText(K, "K=");
  }
  
  
  private UByte T(UByte x) { //x won't change in this function.
    
    //x.printAllFormat("Beginning of T");
    
    UByte Q = lookupTable.lookUp(x.xor(K[0]).addMod256(K[1])).addMod256(x);
    UByte R = lookupTable.lookUp(Q.xor(K[2]).addMod256(K[3])).addMod256(x);
    UByte S = lookupTable.lookUp(R.xor(K[4]).addMod256(K[5])).addMod256(x);
    
    //x.printAllFormat("End of T");
    
    return lookupTable.lookUp(S.xor(K[6]).addMod256(K[7])).addMod256(x);
  }
  
  
  /**
   * Encrypts the given plaintext and returns the encrypted text as hex string.
   * 
   * @param plaintext the given plaintext
   * @return the encrypted text as string of hex digits
   */
  public String encrypt(String plaintext) {
    
    // it checks the size to be dividable by 4 as well.
    Word[] plaintextWordArr = ConversionUtil.textToWordArr(plaintext);
    Word[] ciphertextWordArr = new Word[plaintextWordArr.length];
    
    int index = 0;
    for (Word block : plaintextWordArr) {
      ciphertextWordArr[index++] = round_3(round_2(round_1(block)));
    }
    
    return ConversionUtil.wordArrToHexStr(ciphertextWordArr);
  }
  
  
  /**
   * Decrypts the input cipherHexStr and returns the plaintext as text.
   * 
   * @param cipherHexStr the input as a string of hex digits
   * @return the decrypted text
   */
  public String decrypt(String cipherHexStr) {
    
    Word[] ciphertextWordArr = ConversionUtil.hexStrToWordArr(cipherHexStr);
    Word[] plaintextWordArr = new Word[ciphertextWordArr.length];
    
    int index = 0;
    for (Word block : ciphertextWordArr) {
      plaintextWordArr[index++] = round_3(round_2(round_1(block)));
    }
    
    return ConversionUtil.wordArrToText(plaintextWordArr);
  }
  
  
  private Word round_1(Word block) { //block is mutable.
    UByte z = UByte.constructFromInteger(0);
    
    for (int i = 0; i < BLOCK_SIZE_BYTES; i++) {
      UByte I = UByte.constructFromInteger(i);
      UByte k = T(z.xor(I));
      UByte pI = block.byteAtM(i);
      pI.addMod256M(k);
      z.addMod256M(pI);
    }
    return block;
  }
  
  
  private Word round_2(Word block) {
    UByte one = UByte.constructFromInteger(1);
    
    for (int i = 0; i < BLOCK_SIZE_BYTES / 2; i++) {
      UByte pI = block.byteAtM(i);
      UByte pJ = block.byteAt(BLOCK_SIZE_BYTES - 1 - i);
      pI.xorM((pJ.or(one)));
    }
    return block;
  }
  
  
  private Word round_3(Word block) {
    UByte[] cipherBlockArr = new UByte[BLOCK_SIZE_BYTES];
    UByte z = UByte.constructFromInteger(0);
    
    for (int i = 0; i < BLOCK_SIZE_BYTES; i++) {
      
      UByte I = UByte.constructFromInteger(i);
      UByte pI = block.byteAtM(i);
      UByte k = T(z.xor(I));
      z.addMod256M(pI);
      cipherBlockArr[i] = pI.subtractMod256(k);
    }
    
    return Word.constructFromUByteArr(cipherBlockArr);
  }
  
}
