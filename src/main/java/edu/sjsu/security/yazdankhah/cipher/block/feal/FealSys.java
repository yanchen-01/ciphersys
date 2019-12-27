package edu.sjsu.security.yazdankhah.cipher.block.feal;

import edu.sjsu.security.abstracts.FealAbs;
import edu.sjsu.security.cipherutils.ConversionUtil;
import edu.sjsu.security.cipherutils.PrintUtil;
import edu.sjsu.security.cipherutils.StringUtil;
import edu.sjsu.security.primitivedatatypes.DByte;
import edu.sjsu.security.primitivedatatypes.DWord;
import edu.sjsu.security.primitivedatatypes.UByte;
import edu.sjsu.security.primitivedatatypes.Word;
import lombok.extern.slf4j.Slf4j;


/**
 * Simulates FEAL block cipher.
 * 
 * @author ahmad
 */
@Slf4j
public class FealSys extends FealAbs {
  
  private DByte[] SK;
  private DWord SK_89AB; // Both should be initialize after SK is generated.
  private DWord SK_CDEF;
  // private Step step = Step.initialize();
  
  
  /**
   * Constructs a new object of FealSys. If the pass is not at least 8 characters, then it will be
   * padded by spaces on the right.
   * 
   * @param passText the provide pass key in text
   */
  public FealSys(String passText) {
    
    log.info("original passText = [" + passText + "]");
    
    passText = StringUtil.rightTruncRightPadWithZeros(passText, DWORD_SIZE_TEXT);
    log.info("after padding passText = [" + passText + "]");
    
    DWord K = DWord.constructFromText(passText); 
    
    SK = generateSubKeys(K);
    SK_89AB = DWord.constructFrom4DBytes(SK[8], SK[9], SK[10], SK[11]);
    SK_CDEF = DWord.constructFrom4DBytes(SK[12], SK[13], SK[14], SK[15]);
    
  }
  
  
  private DByte[] generateSubKeys(DWord K) {
    
    K.printAllFormat("pass key");
    
    DByte[] subK = new DByte[SUBKEYS_ARRAY_SIZE];
    Word[] A = new Word[SUBKEYS_ARRAY_SIZE / 2 + 1];
    Word[] B = new Word[SUBKEYS_ARRAY_SIZE / 2 + 1];
    Word D = Word.constructFromLong(0);
    
    A[0] = K.leftWord();
    B[0] = K.rightWord();
    
    for (int i = 0; i < SUBKEYS_ARRAY_SIZE / 2; i++) {
      
      A[i + 1] = B[i];
      B[i + 1] = Fk(A[i], B[i].xor(D));
      
      subK[2 * i] = B[i + 1].leftDByte();
      subK[2 * i + 1] = B[i + 1].rightDByte();
      
      D = A[i];
    }
    
    return subK;
  }
  
  
  public static Word Fk(Word x, Word y) {
    
    UByte x0 = x.byteAt(0), x1 = x.byteAt(1), x2 = x.byteAt(2), x3 = x.byteAt(3);
    UByte y0 = y.byteAt(0), y1 = y.byteAt(1), y2 = y.byteAt(2), y3 = y.byteAt(3);
    
    UByte z1 = S(x0.xor(x1), x2.xor(x3).xor(y0), 1);
    UByte z0 = S(x0, z1.xor(y2), 0);
    UByte z2 = S(x2.xor(x3), z1.xor(y1), 0);
    UByte z3 = S(x3, z2.xor(y3), 1);
    
    UByte[] uByteArr = { z0, z1, z2, z3 };
    return Word.constructFromUByteArr(uByteArr);
  }
  
  
  public static Word F(Word x, DByte y) {
    
    UByte x0 = x.byteAt(0), x1 = x.byteAt(1), x2 = x.byteAt(2), x3 = x.byteAt(3);
    UByte y0 = y.byteAt(0), y1 = y.byteAt(1);
    
    UByte z1 = S(x1.xor(y0).xor(x0), x2.xor(y1).xor(x3), 1);
    UByte z0 = S(x0, z1, 0);
    UByte z2 = S(z1, x2.xor(y1).xor(x3), 0);
    UByte z3 = S(z2, x3, 1);
    
    UByte[] uByteArr = { z0, z1, z2, z3 };
    return Word.constructFromUByteArr(uByteArr);
  }
  
  
  private DWord encryptOneBlcok(DWord p, DByte[] sk) {
    
    Word[] L = new Word[9], R = new Word[9];
    
    p.xorM(SK_89AB);
    DWord lZero = DWord.constructFrom2Words(WORD0, p.leftWord());
    p.xorM(lZero);
    
    L[0] = p.leftWord();
    R[0] = p.rightWord();
    
    for (int r = 1; r <= ROUND; r++) {
      Word f = F(R[r - 1], SK[r - 1]);
      R[r] = L[r - 1].xor(f);
      L[r] = R[r - 1];
    }
    
    DWord rZero = DWord.constructFrom2Words(WORD0, R[8]);
    DWord dw8 = DWord.constructFrom2Words(R[8], L[8]);
    dw8.xorM(rZero);
    dw8.xorM(SK_CDEF);
    
    return dw8;
  }
  
  
  private DWord decryptOneBlcok(DWord c, DByte[] sk) {
    
    c.printHexStr("decryption c");
    
    Word[] L = new Word[9], R = new Word[9];
    
    c.xorM(SK_CDEF); // c = (R8 , L8)
    DWord rZero = DWord.constructFrom2Words(WORD0, c.leftWord()); // = (0 , R8)
    c.xorM(rZero);
    
    R[8] = c.leftWord();
    L[8] = c.rightWord();
    
//    R[8].printHexStr("R[8]");
//    L[8].printHexStr("L[8]");
    
    for (int r = ROUND; r >= 1; r--) {
      Word f = F(L[r], SK[r - 1]);
      L[r - 1] = R[r].xor(f);
      R[r - 1] = L[r];
    }
    
//    R[0].printHexStr("R[0]");
//    L[0].printHexStr("L[0]");
    DWord lZero = DWord.constructFrom2Words(WORD0, L[0]);
    DWord dw0 = DWord.constructFrom2Words(L[0], R[0]);
    dw0.xorM(lZero);
    dw0.xorM(SK_89AB);
    //dw0.printHexStr("dw0");
    
    return dw0;
  }
  
  
  /**
   * Encrypts the given plaintext and returns the encrypted text as hex string.
   * 
   * @param plaintext the given plaintext
   * @return the encrypted text as string of hex digits
   */
  public String encrypt(String plaintext) {
    
    DWord[] plaintextBlockArr = ConversionUtil.textToDWordArr(plaintext); //1
    DWord[] ciphertextBlockArr = new DWord[plaintextBlockArr.length];
    
    int index = 0;
    for (DWord block : plaintextBlockArr) {
      ciphertextBlockArr[index++] = encryptOneBlcok(block, SK);
    }
    
    return ConversionUtil.dwordArrToHexStr(ciphertextBlockArr);
  }
  
  
  /**
   * Decrypts the input cipherHexStr and returns the plaintext as text.
   * 
   * @param cipherHexStr the input as a string of hex digits
   * @return the decrypted text
   */
  public String decrypt(String cipherHexStr) {
    
    DWord[] ciphertextBlockArr = ConversionUtil.hexStrToDWordArr(cipherHexStr);
    DWord[] plaintextBlockArr = new DWord[ciphertextBlockArr.length];
    
    int index = 0;
    for (DWord block : ciphertextBlockArr) {
      plaintextBlockArr[index++] = decryptOneBlcok(block, SK);
    }
    
    return ConversionUtil.dwordArrToText(plaintextBlockArr).trim();
  }
  
  
  @Override
  public void printSubKeysArray(String debugMsg) {
    log.info("\n............... SUBKEYS ...................");
    PrintUtil.printDByteArrAllFormats(SK);
  }
  
}
