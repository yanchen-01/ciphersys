package edu.sjsu.yazdankhah.crypto.ciphersys.block.aes;

import edu.sjsu.yazdankhah.crypto.util.abstracts.AesAbs;
import edu.sjsu.yazdankhah.crypto.util.ciphersysdatatypes.AesState;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.ConversionUtil;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.PrintUtil;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.StringUtil;
import edu.sjsu.yazdankhah.crypto.util.primitivedatatypes.Word;
import lombok.extern.slf4j.Slf4j;


/**
 * Simulates AES block cipher.
 * 
 * @author ahmad
 */
@Slf4j
public class AesSys extends AesAbs {
  
  private AesState[] SK;
  

  public AesSys(String passText) {
    
    String binStr = ConversionUtil.textToBinStr(passText);
//    String binStr = ConversionUtil.hexStrToBinStr(passText);
    binStr = StringUtil.rightTruncRightPadWithZeros(binStr, AES_KEY_SIZE_BITS);
    AesState subKey0 = AesState.constructFromBinStr(binStr);
    
    SK = keyExpansion(subKey0);
  }
  
  
  private static AesState oneRoundKeyExpansion(AesState q, int round) {
    
    Word[] wordArr = q.clone().toWordArr();
    
    wordArr[0].xorM(g(wordArr[3], round));
    wordArr[1].xorM(wordArr[0]);
    wordArr[2].xorM(wordArr[1]);
    wordArr[3].xorM(wordArr[2]);
    
    return AesState.constructFromWordArr(wordArr);
  }
  
  
  public static AesState[] keyExpansion(AesState subKey0) {
    
    AesState[] subKArr = new AesState[SUBKEYS_ARRAY_SIZE];
    subKArr[0] = subKey0;
    
    for (int round = 1; round < SUBKEYS_ARRAY_SIZE; round++) {
      subKArr[round] = oneRoundKeyExpansion(subKArr[round - 1], round);
    }
    
    return subKArr;
  }
  
  
  /**
   * Performs the g-function of key expansion on a given word and given round and returns the result.
   * 
   * @param w0 the given word
   * @param round the given round
   * @return the result of the g-function
   */
  public static Word g(Word w0, int round) {
    
    Word w1 = w0.rotateLeftBytes();
    w1 = w1.lookUp(AES_SBOX);
    w1.byteAtM(0).xorM(RC[round - 1]);
    
    return w1;
  }
  
  
  private AesState encryptOneBlcok(AesState block) {
    
    block.addRoundKeyM(SK[0]);                          block.printHexStrFormatted("after round 0");
    
    for (int round = 1; round < AES_ROUND; round++) {
      block.printHexStrFormatted("*** start of round " + round + " ***");
      block.byteSubM(AES_SBOX);                         block.printHexStrFormatted("after byteSub");
      block.shiftRowM();                                block.printHexStrFormatted("after shiftRow");
      block.mixColumnM(AES_MIX_COLUMN_CONSTANT_STATE);  block.printHexStrFormatted("after mix col");
      block.addRoundKeyM(SK[round]);                    SK[round].printHexStrFormatted("sub key round = " + round);
    }
    
    // Round 10 does not have mixColumn
    block.byteSubM(AES_SBOX);                          block.printHexStrFormatted("after byteSub 10");
    block.shiftRowM();                                 block.printHexStrFormatted("after shiftRow 10");
    block.addRoundKeyM(SK[AES_ROUND]);                 SK[AES_ROUND].printHexStrFormatted("sub key 10");
    
    return block;
  }
  
  
  
  private AesState decryptOneBlcok(AesState block) {
    
    block.addRoundKeyM(SK[AES_ROUND]);
    block.invShiftRowM();
    block.byteSubM(AES_INVERSE_SBOX);
//    block.printHexStrFormatted("first add key");
    
    for (int round = AES_ROUND-1; round > 0; round--) {
      //block.printHexStrFormatted("start of round " + round);
      
      block.addRoundKeyM(SK[round]);
      block.mixColumnM(AES_INV_MIX_COLUMN_CONSTANT_STATE);
      block.invShiftRowM();
      block.byteSubM(AES_INVERSE_SBOX);
      
      // block.printHexStrFormatted("after add key");
      // block.printHexStrFormatted("after mix col");
      // block.printHexStrFormatted("after shiftRow");
      // block.printHexStrFormatted("after byteSub");
      // SK[round].printHexStrFormatted("Round Key");
    }
    
    // Round 0 does not have mixColumn
   
    block.addRoundKeyM(SK[0]);
    //block.printHexStrFormatted("final block");
    
    return block;
  }
  
  
  
  @Override
  public String encrypt(String plaintext) {
    
    AesState[] plaintextBlockArr = ConversionUtil.textToAesStateArr(plaintext); 
//    AesState[] plaintextBlockArr = ConversionUtil.hexStrToAesStateArr(plaintext);
    AesState[] ciphertextBlockArr = new AesState[plaintextBlockArr.length];
    
    int index = 0;
    for (AesState block : plaintextBlockArr) {
      ciphertextBlockArr[index++] = encryptOneBlcok(block);
    }
    
    return ConversionUtil.aesStateArrToHexStr(ciphertextBlockArr);
  }
  
  
  @Override
  public String decrypt(String cipherHexStr) {
    
    AesState[] ciphertextBlockArr = ConversionUtil.hexStrToAesStateArr(cipherHexStr);
    AesState[] plaintextBlockArr  = new AesState[ciphertextBlockArr.length];
    
    int index = 0;
    for (AesState block : ciphertextBlockArr) {
      plaintextBlockArr[index++] = decryptOneBlcok(block);
    }
    
//    return ConversionUtil.aesStateArrToHexStr(ciphertextBlockArr);
    
    return ConversionUtil.aesStateArrToText(ciphertextBlockArr);
  }
  
  
  @Override
  public void printSubKeysArray() {
    log.info("\n............... SUBKEYS ...................");
    PrintUtil.printAesStateArrHexStrFormatted(SK);
  }
  
}
