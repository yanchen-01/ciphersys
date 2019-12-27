package edu.sjsu.yazdankhah.crypto.ciphersys.block.des;

import edu.sjsu.yazdankhah.crypto.util.abstracts.DesAbs;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.ConversionUtil;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.PrintUtil;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.StringUtil;
import edu.sjsu.yazdankhah.crypto.util.primitivedatatypes.DWord;
import edu.sjsu.yazdankhah.crypto.util.primitivedatatypes.Word;
import edu.sjsu.yazdankhah.crypto.util.shiftregisters.ShiftReg;
import lombok.extern.slf4j.Slf4j;


/**
 * Simulates DES block cipher.
 * 
 * @author ahmad
 */
@Slf4j
public class DesSys extends DesAbs {
  
  private ShiftReg[] SK;
  
  
  public DesSys(String passText) {
    
    //SK = new ShiftReg[SUBKEYS_ARRAY_SIZE];
//    log.info("original passText = [" + passText + "]");
    
    String binStr = ConversionUtil.textToBinStr(passText);
    binStr = StringUtil.rightTruncRightPadWithZeros(binStr, KEY_SIZE_BITS);
    ShiftReg key64 = ShiftReg.constructFromBinStr(binStr); // 64-bit
    
    SK = keyExpansion(key64);
  }
  
  
  /**
   * Simulates DES function.
   * 
   * @post-requisite the arguments won't change 
   * @param w the input block of data 
   * @param k48 the subkey
   * @return result of the F
   */
  public static Word F(final Word w, final ShiftReg k48) {
    
    ShiftReg sr32 = w.toShiftReg();
    ShiftReg sr48 = sr32.bitsAt(EXPANSION_BITS);
    sr48.xorM(k48);
    ShiftReg[] sboxInputs6 = sr48.toArr(SBOXES_NUM);
    ShiftReg[] sboxOutputs4 = new ShiftReg[SBOXES_NUM];
    
    for (int i=0; i< SBOXES_NUM; i++) {
      sboxOutputs4[i] = SBOXES[i].lookup(sboxInputs6[i]);
    }
    
    String binStr = ConversionUtil.shiftRegArrToBinStr(sboxOutputs4);
    return Word.constructFromBinStr(binStr);
  }
  
  
  private static ShiftReg[] keyExpansion(final ShiftReg key64) {
    
    ShiftReg[] subKArr = new ShiftReg[SUBKEYS_ARRAY_SIZE];
    
    ShiftReg key56 = key64.bitsAt(KEY_INITIAL_PERMUTATION_BITS);
    //key56.printAllFormat("key56");
    
    ShiftReg leftKey28  = key56.subShiftReg(0, 27); // 28-bit
    ShiftReg rightKey28 = key56.subShiftReg(28, 55); // 28-bit
    
    for (int round = 0; round < DES_ROUND; round++) {
      
//      leftKey28.printAllFormat("Left");
//      rightKey28.printAllFormat("right\n");
      
      leftKey28.rotateLeftNTimesM(ROUNDS_ROTATE_TIMES[round]);
      rightKey28.rotateLeftNTimesM(ROUNDS_ROTATE_TIMES[round]);
      
      ShiftReg keyI = leftKey28.concatenateRight(rightKey28);
      subKArr[round] = keyI.bitsAt(KEY_FINAL_PERMUTATION_BITS); //48-bit
      //subKArr[round].printAllFormat("K"+round);
    }
    
    return subKArr;
  }
  
  
  private DWord encryptOneBlcok(DWord block) {
    
    block.permutateM(DES_INITIAL_PERMUTATION_BITS);
    
    Word L = block.leftWordM();
    Word R = block.rightWordM();
    Word tempL;
    
    for (int round=0; round < DES_ROUND; round++) {
      tempL = L.clone();
      L = R.clone(); //This clone is critical.
      R = tempL.xorM(F(R, SK[round]));
    }
    
    block.swapWordsM();
    block.permutateM(DES_FINAL_PERMUTATION_BITS);
    return block;
  }
  
  

  private DWord decryptOneBlcok(DWord block) {
    
    block.permutateM(DES_INITIAL_PERMUTATION_BITS);
    block.swapWordsM();
    
    Word L = block.leftWordM();
    Word R = block.rightWordM();
    Word tempL;
    
    for (int round=DES_ROUND-1; round > 0; round--) {
      tempL = R.clone();
      R = L.clone();  //This clone is critical.
      L = tempL.xorM(F(L, SK[round]));
    }
    
    block.permutateM(DES_FINAL_PERMUTATION_BITS);
    return block;
  }

  
  
  @Override
  public String encrypt(String plaintext) {
    
    DWord[] plaintextBlockArr = ConversionUtil.textToDWordArr(plaintext); //64-bit blocks
    DWord[] ciphertextBlockArr = new DWord[plaintextBlockArr.length];
    
    int index = 0;
    for (DWord block : plaintextBlockArr) {
      ciphertextBlockArr[index++] = encryptOneBlcok(block);
    }
    
    return ConversionUtil.dwordArrToHexStr(ciphertextBlockArr);
    
  }
  
  
  @Override
  public String decrypt(String cipherHexStr) {

    DWord[] ciphertextBlockArr = ConversionUtil.hexStrToDWordArr(cipherHexStr);
    DWord[] plaintextBlockArr = new DWord[ciphertextBlockArr.length];
    
    int index = 0;
    for (DWord block : ciphertextBlockArr) {
      plaintextBlockArr[index++] = decryptOneBlcok(block);
    }
    
    return ConversionUtil.dwordArrToText(plaintextBlockArr).trim();
    
  }
  
  
  @Override
  public void printSubKeysArray() {
    log.info("\n............... SUBKEYS ...................");
    PrintUtil.printShiftRegArrAllFormats(SK);
    
  }
  
}
