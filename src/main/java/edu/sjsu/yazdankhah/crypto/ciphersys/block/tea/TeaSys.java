package edu.sjsu.yazdankhah.crypto.ciphersys.block.tea;

import edu.sjsu.yazdankhah.crypto.util.abstracts.TeaAbs;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.ConversionUtil;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.StringUtil;
import edu.sjsu.yazdankhah.crypto.util.primitivedatatypes.DWord;
import edu.sjsu.yazdankhah.crypto.util.primitivedatatypes.Quad;
import edu.sjsu.yazdankhah.crypto.util.primitivedatatypes.Word;
import lombok.extern.slf4j.Slf4j;

/**
 * Simulates TEA block cipher.
 * 
 * @author ahmad
 */
@Slf4j
public class TeaSys extends TeaAbs  {
  
  private Quad SK;
  
  
  public TeaSys(String passText) {
    
    String binStr = ConversionUtil.textToBinStr(passText);
//    String binStr = ConversionUtil.hexStrToBinStr(passText);
    binStr = StringUtil.rightTruncRightPadWithZeros(binStr, TEA_KEY_SIZE_BITS);
    SK = Quad.constructFromBinStr(binStr);      //SK.printHexStr("SK");
  }
  
  
  private DWord encryptOneBlcok(DWord block) {
    
    Word L = block.leftWord();
    Word R = block.rightWord();
    Word sum = Word.constructFromLong(0L);
    
    for (int round = 0; round < TEA_ROUND; round++) {
      
      sum.addMod2p32M(DELTA);                               //sum.printHexStr("round = " + round);
      
      Word w1 = R.shiftLeft(4).addMod2p32M(SK.wordAt(0));
      Word w2 = R.addMod2p32(sum);
      Word w3 = R.shiftRight(5).addMod2p32M(SK.wordAt(1));
      L.addMod2p32M(w1.xorM(w2.xorM(w3)));                  //R.printHexStr("enc L round " + round);
      
      w1 = L.shiftLeft(4).addMod2p32M(SK.wordAt(2));
      w2 = L.addMod2p32(sum);
      w3 = L.shiftRight(5).addMod2p32M(SK.wordAt(3));
      R.addMod2p32M(w1.xorM(w2.xorM(w3)));                  //R.printHexStr("enc R round " + round);
    }
    
    return DWord.constructFrom2Words(L, R);
  }
  
  
  
  private DWord decryptOneBlcok(DWord block) {
    
    Word L = block.leftWord();        //L.printHexStr("dec beg L");
    Word R = block.rightWord();       //R.printHexStr("dec beg R");
    Word sum = DELTA.shiftLeft(5);    //sum.printHexStr("dec delta"); DELTA.printHexStr("dec Delta");
    
    for (int round = 0; round < TEA_ROUND; round++) {
      
      Word w1 = L.shiftLeft(4).addMod2p32M(SK.wordAt(2));
      Word w2 = L.addMod2p32(sum);
      Word w3 = L.shiftRight(5).addMod2p32M(SK.wordAt(3));
      R.subtractMod2p32M(w1.xorM(w2.xorM(w3)));    //R.printHexStr("dec R round " + round);
      
      
      w1 = R.shiftLeft(4).addMod2p32M(SK.wordAt(0));
      w2 = R.addMod2p32(sum);
      w3 = R.shiftRight(5).addMod2p32M(SK.wordAt(1));
      L.subtractMod2p32M(w1.xorM(w2.xorM(w3)));    //L.printHexStr("dec L round " + round);
      
      sum.subtractMod2p32M(DELTA);
    }
    
    return DWord.constructFrom2Words(L, R);
  }
  

  @Override
  public String encrypt(String plaintext) {
    
    //text will be right-padded with spaces if the size is not suitable.
    DWord[] plaintextBlockArr = ConversionUtil.textToDWordArr(plaintext); 
//    DWord[] plaintextBlockArr = ConversionUtil.hexStrToDWordArr(plaintext);
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
    DWord[] plaintextBlockArr  = new DWord[ciphertextBlockArr.length];
    
    int index = 0;
    for (DWord block : ciphertextBlockArr) {
      plaintextBlockArr[index++] = decryptOneBlcok(block);
    }
    
//    return ConversionUtil.dwordArrToHexStr(plaintextBlockArr);
    
    return ConversionUtil.dwordArrToText(plaintextBlockArr);
  }
  

  
  @Override
  public void printSubKeysArray() {
    SK.printHexStr("SK");
  }
  
}
