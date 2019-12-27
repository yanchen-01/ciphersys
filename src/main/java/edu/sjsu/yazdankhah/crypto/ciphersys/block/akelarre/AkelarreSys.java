package edu.sjsu.yazdankhah.crypto.ciphersys.block.akelarre;

import edu.sjsu.yazdankhah.crypto.util.abstracts.AkelarreAbs;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.ConversionUtil;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.PrintUtil;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.Step;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.StringUtil;
import edu.sjsu.yazdankhah.crypto.util.primitivedatatypes.DByte;
import edu.sjsu.yazdankhah.crypto.util.primitivedatatypes.DWord;
import edu.sjsu.yazdankhah.crypto.util.primitivedatatypes.Quad;
import edu.sjsu.yazdankhah.crypto.util.primitivedatatypes.Word;
import lombok.extern.slf4j.Slf4j;


/**
 * Simulates block cipher Akelarre.
 * 
 * @author ahmad
 */
@Slf4j
public class AkelarreSys extends AkelarreAbs {
  
  private Word[] ENCRYPTION_SUB_KEYS; // 13*round+9; for round=4, size=61
  private Word[] DECRYPTION_SUB_KEYS; // 13*round+9; for round=4, size=61
  private DByte[] si; // 8 si's
  private Word[] ui = new Word[UIs_NUM];
  
  private Step step = Step.initialize();
  
  
  
  
  /**
   * Constructs a new object of CmeaSys. If the pass is not at least 8 characters, then it will be
   * padded by 0's on the right.
   * 
   * @param passText the provide pass key in text
   */
  public AkelarreSys(String passText) {
    
    si = ConversionUtil.binStrToDByteArr(ConversionUtil.textToBinStr(passText)); // 8 si's
    ENCRYPTION_SUB_KEYS = generateEncryptionSubKeys();
    DECRYPTION_SUB_KEYS = generateDecryptionSubKeys();
  }
  
  
  private void keyExpansionInitializeUis() {
    
    for (int i = 0; i < 8; i++) {
      ui[i * 2] = calculateUi(si[i], A1);
      ui[i * 2 + 1] = calculateUi(si[i], A0);
    }
  }
  
  
  private void keyExpansionUpdateUis() {
    
    for (int i = 0; i < 8; i++) {
      DByte tempUi = DByte.constructFromBinStr(ui[i * 2].bitRangeToBinStr(8, 23)); //??? 23 OR 24
      DByte tempUiP1 = DByte.constructFromBinStr(ui[i * 2 + 1].bitRangeToBinStr(8, 23));
      ui[i * 2] = calculateUi(tempUi, A1);
      ui[i * 2 + 1] = calculateUi(tempUiP1, A0);
    }
  }
  
  
  /**
   * @prerequisite the subKeys for Encryption has already been generated and this method
   * only reverse it and makes some modifications required for this algorithm.
   */
  private Word[] generateDecryptionSubKeys() {
    
    Word[] decSubKey = new Word[SUBKEYS_ARRAY_SIZE];
    final int R_X_13 = R * 13;
    
    
    // Input Transformation
    decSubKey[0] = ENCRYPTION_SUB_KEYS[R_X_13 + 5].negateMod2p32();
    decSubKey[1] = ENCRYPTION_SUB_KEYS[R_X_13 + 6];
    decSubKey[2] = ENCRYPTION_SUB_KEYS[R_X_13 + 7];
    decSubKey[3] = ENCRYPTION_SUB_KEYS[R_X_13 + 8].negateMod2p32();
    
    // Output Transformation
    decSubKey[R_X_13 + 4] = ENCRYPTION_SUB_KEYS[4].negateBitRangeMod2p32(ROTATION_KEY_START_BIT, ROTATION_KEY_END_BIT);
    decSubKey[R_X_13 + 5] = ENCRYPTION_SUB_KEYS[0].negateMod2p32();
    decSubKey[R_X_13 + 6] = ENCRYPTION_SUB_KEYS[1];
    decSubKey[R_X_13 + 7] = ENCRYPTION_SUB_KEYS[2];
    decSubKey[R_X_13 + 8] = ENCRYPTION_SUB_KEYS[3].negateMod2p32();
    
    // Round Transformation
    for (int r = 0; r < R; r++) {
      int rx13 = r * 13;
      decSubKey[rx13 + 4] = ENCRYPTION_SUB_KEYS[13 * (R - r) + 4].negateBitRangeMod2p32(ROTATION_KEY_START_BIT, ROTATION_KEY_END_BIT); // offset=4
      
      for (int offset = 5; offset <= 16; offset++) {
        decSubKey[rx13 + offset] = ENCRYPTION_SUB_KEYS[13 * (R - r - 1) + offset]; // offset=5
      }
    }//round
    
    return decSubKey;
  }
  
  
  private Word[] generateEncryptionSubKeys() {
    
    Word[] subK = new Word[SUBKEYS_ARRAY_SIZE];
    keyExpansionInitializeUis();
    
    int total = 0; //to make the number of subkeys 13*R+9
    for (int offset = 0; offset < 8; offset++) {
      
      for (int i = 0; i < 8 & total < SUBKEYS_ARRAY_SIZE; i++) {
        String subKeyBinStr = ui[i * 2 + 1].bitRangeToBinStr(24, 31) + ui[i * 2 + 1].bitRangeToBinStr(0, 7)
            + ui[(i * 2 + 2) % MOD_8].bitRangeToBinStr(24, 31) + ui[(i * 2 + 2) % MOD_8].bitRangeToBinStr(0, 7);
        
        subK[offset*8 + i] = Word.constructFromBinStr(subKeyBinStr);
        total++;
      }
      
      keyExpansionUpdateUis();
    }
    
    return subK;
  }
  
  
  private Quad oneRoundEncryption(Quad A, int r, Word[] subK) {
    
    int offset = 13 * r;
    step.savePrevious(A.toBinStrFormatted(), offset + 4);
    
    // Keyed Rotation: the right-most 7 bits
    int times = subK[offset + 4].bitRangeToInteger(ROTATION_KEY_START_BIT, ROTATION_KEY_END_BIT); 
    A.rotateLeftNTimesM(times);  
    step.save(A.toBinStrFormatted(), subK[offset + 4].toBinStrFormatted(), offset + 4);
    
    // the output of keyed rotation
    Word B0 = A.wordAt(0);
    Word B1 = A.wordAt(1);
    Word B2 = A.wordAt(2);
    Word B3 = A.wordAt(3);
    
    // AR function
    DWord T = AR(B0.xor(B2), B1.xor(B3), offset, subK);
    Word T0 = T.wordAt(0);
    Word T1 = T.wordAt(1);
    
    // output of the round
    Word D0 = B0.xor(T1);
    Word D1 = B1.xor(T0);
    Word D2 = B2.xor(T1);
    Word D3 = B3.xor(T0);
    
    Word[] wordArr = { D0, D1, D2, D3 };
    return Quad.constructFromWordArr(wordArr);
  }
  
  
  private DWord AR(Word W0, Word W1, int offset, Word[] subK) {
    
    W1.rotateLeftBitRangeNTimesM(0, 30, W0.bitRangeToInteger(27, 31));
    step.savePrevious(W1.toBinStrFormatted(), offset + 5);
    W1.addMod2p32M(subK[offset + 5]);   
    step.save(W1.toBinStrFormatted(), subK[offset + 5].toBinStrFormatted(), offset + 5);
    
    W1.rotateLeftBitRangeNTimesM(1, 31, W0.bitRangeToInteger(22, 26));
    step.savePrevious(W1.toBinStrFormatted(), offset + 6);
    W1.addMod2p32M(subK[offset + 6]);
    step.save(W1.toBinStrFormatted(), subK[offset + 6].toBinStrFormatted(), offset + 6);
    
    W1.rotateLeftBitRangeNTimesM(0, 30, W0.bitRangeToInteger(17, 21));
    step.savePrevious(W1.toBinStrFormatted(), offset + 7);
    W1.addMod2p32M(subK[offset + 7]);
    step.save(W1.toBinStrFormatted(), subK[offset + 7].toBinStrFormatted(), offset + 7);
    
    W1.rotateLeftBitRangeNTimesM(1, 31, W0.bitRangeToInteger(12, 16));
    step.savePrevious(W1.toBinStrFormatted(), offset + 8);
    W1.addMod2p32M(subK[offset + 8]);
    step.save(W1.toBinStrFormatted(), subK[offset + 8].toBinStrFormatted(), offset + 8);
    
    W1.rotateLeftBitRangeNTimesM(0, 30, W0.bitRangeToInteger(8, 11));
    step.savePrevious(W1.toBinStrFormatted(), offset + 9);
    W1.addMod2p32M(subK[offset + 9]);
    step.save(W1.toBinStrFormatted(), subK[offset + 9].toBinStrFormatted(), offset + 9);
    
    W1.rotateLeftBitRangeNTimesM(1, 31, W0.bitRangeToInteger(4, 7));
    step.savePrevious(W1.toBinStrFormatted(), offset + 10);
    W1.addMod2p32M(subK[offset + 10]);
    step.save(W1.toBinStrFormatted(), subK[offset + 10].toBinStrFormatted(), offset + 10);
    
    W1.rotateLeftBitRangeNTimesM(0, 30, W0.bitRangeToInteger(0, 3));
    
    /* ................................................................. */
    
    W0.rotateLeftBitRangeNTimesM(0, 30, W1.bitRangeToInteger(27, 31));
    step.savePrevious(W0.toBinStrFormatted(), offset + 11);
    W0.addMod2p32M(subK[offset + 11]);
    step.save(W0.toBinStrFormatted(), subK[offset + 11].toBinStrFormatted(), offset + 11);
    
    W0.rotateLeftBitRangeNTimesM(1, 31, W1.bitRangeToInteger(22, 26));
    step.savePrevious(W0.toBinStrFormatted(), offset + 12);
    W0.addMod2p32M(subK[offset + 12]);
    step.save(W0.toBinStrFormatted(), subK[offset + 12].toBinStrFormatted(), offset + 12);
    
    W0.rotateLeftBitRangeNTimesM(0, 30, W1.bitRangeToInteger(17, 21));
    step.savePrevious(W0.toBinStrFormatted(), offset + 13);
    W0.addMod2p32M(subK[offset + 13]);
    step.save(W0.toBinStrFormatted(), subK[offset + 13].toBinStrFormatted(), offset + 13);
    
    W0.rotateLeftBitRangeNTimesM(1, 31, W1.bitRangeToInteger(12, 16));
    step.savePrevious(W0.toBinStrFormatted(), offset + 14);
    W0.addMod2p32M(subK[offset + 14]);
    step.save(W0.toBinStrFormatted(), subK[offset + 14].toBinStrFormatted(), offset + 14);
    
    W0.rotateLeftBitRangeNTimesM(0, 30, W1.bitRangeToInteger(8, 11));
    step.savePrevious(W0.toBinStrFormatted(), offset + 15);
    W0.addMod2p32M(subK[offset + 15]);
    step.save(W0.toBinStrFormatted(), subK[offset + 15].toBinStrFormatted(), offset + 15);
    
    W0.rotateLeftBitRangeNTimesM(1, 31, W1.bitRangeToInteger(4, 7));
    step.savePrevious(W0.toBinStrFormatted(), offset + 16);
    W0.addMod2p32M(subK[offset + 16]);
    step.save(W0.toBinStrFormatted(), subK[offset + 16].toBinStrFormatted(), offset + 16);
    
    W0.rotateLeftBitRangeNTimesM(0, 30, W1.bitRangeToInteger(0, 3));
    
    Word[] wordArr = { W0, W1 };
    return DWord.constructFromWordArr(wordArr);
  }
  
  
  private Quad outputTransformation(Quad X, Word[] subK) {
    
    int offset = 13*R;
    
    int times = subK[offset + 4].bitRangeToInteger(ROTATION_KEY_START_BIT, ROTATION_KEY_END_BIT);
    step.savePrevious(X.toBinStrFormatted(), offset + 4);
    X.rotateLeftNTimesM(times);                  
    step.save(X.toBinStrFormatted(), subK[offset + 4].toBinStrFormatted(), offset+4);
    
    step.savePrevious(X.wordAtM(3).toBinStrFormatted(), offset + 5);
    X.wordAtM(0).addMod2p32M(subK[offset + 5]);  
    step.save(X.wordAtM(0).toBinStrFormatted(), subK[offset + 5].toBinStrFormatted(), offset + 5);
    
    step.savePrevious(X.wordAtM(3).toBinStrFormatted(), offset + 6);
    X.wordAtM(1).xorM(subK[offset + 6]);         
    step.save(X.wordAtM(1).toBinStrFormatted(), subK[offset + 6].toBinStrFormatted(), offset + 6);
    
    step.savePrevious(X.wordAtM(3).toBinStrFormatted(), offset + 7);
    X.wordAtM(2).xorM(subK[offset + 7]);         
    step.save(X.wordAtM(2).toBinStrFormatted(), subK[offset + 7].toBinStrFormatted(), offset + 7);
    
    step.savePrevious(X.wordAtM(3).toBinStrFormatted(), offset + 8);
    X.wordAtM(3).addMod2p32M(subK[offset + 8]);  
    step.save(X.wordAtM(3).toBinStrFormatted(), subK[offset + 8].toBinStrFormatted(), offset + 8);
    
    return X;
  }
  
  
  private Quad inputTransformation(Quad X, Word[] subK) {
    
    step.savePrevious(X.wordAtM(3).toBinStrFormatted(), 0);
    X.wordAtM(0).addMod2p32M(subK[0]);   
    step.save(X.wordAtM(0).toBinStrFormatted(), subK[0].toBinStrFormatted(), 0);
    
    step.savePrevious(X.wordAtM(3).toBinStrFormatted(), 1);
    X.wordAtM(1).xorM(subK[1]);          
    step.save(X.wordAtM(1).toBinStrFormatted(), subK[1].toBinStrFormatted(), 1);
    
    step.savePrevious(X.wordAtM(3).toBinStrFormatted(), 2);
    X.wordAtM(2).xorM(subK[2]);          
    step.save(X.wordAtM(2).toBinStrFormatted(), subK[2].toBinStrFormatted(), 2);
    
    step.savePrevious(X.wordAtM(3).toBinStrFormatted(), 3);
    X.wordAtM(3).addMod2p32M(subK[3]);   
    step.save(X.wordAtM(3).toBinStrFormatted(), subK[3].toBinStrFormatted(), 3);
    
    return X;
  }
  
  
  private Quad encryptOneBlcok(Quad block, Word[] subKeyArr) {
    block = inputTransformation(block, subKeyArr);
    
    for (int r = 0; r < R; r++) {
      block = oneRoundEncryption(block, r, subKeyArr);
    }
    return outputTransformation(block, subKeyArr);
  }
  
  
  /**
   * Encrypts the given plaintext and returns the encrypted text as hex string.
   * 
   * @param plaintext the given plaintext
   * @return the encrypted text as string of hex digits
   */
  public String encrypt(String plaintext) {
    
    Quad[] plaintextBlockArr  = ConversionUtil.textToQuadArr(plaintext);
    Quad[] ciphertextBlockArr = new Quad[plaintextBlockArr.length];
    
    int index = 0;
    for (Quad block : plaintextBlockArr) {
      ciphertextBlockArr[index++] = encryptOneBlcok(block, ENCRYPTION_SUB_KEYS);
    }
    
    return ConversionUtil.quadArrToHexStr(ciphertextBlockArr);
  }
  
  
  /**
   * Decrypts the input cipherHexStr and returns the plaintext as text.
   * 
   * @param cipherHexStr the input as a string of hex digits
   * @return the decrypted text
   */
  public String decrypt(String cipherHexStr) {
    
    Quad[] ciphertextBlockArr = ConversionUtil.hexStrToQuadArr(cipherHexStr);
    Quad[] plaintextBlockArr  = new Quad[ciphertextBlockArr.length];
    
    int index = 0;
    for (Quad block : ciphertextBlockArr) {
      plaintextBlockArr[index++] = encryptOneBlcok(block, DECRYPTION_SUB_KEYS);
    }
    
    return ConversionUtil.quadArrToText(plaintextBlockArr).trim();
  }
  
  
  @Override
  public void printSubKeysArray(String debugMsg) {
    log.info("\n............... ENCRYPTION SUBKEYS ...................");
    PrintUtil.printWordArrAllFormats(ENCRYPTION_SUB_KEYS);
    log.info("\n............... DECRYPTION SUBKEYS ...................");
    PrintUtil.printWordArrAllFormats(DECRYPTION_SUB_KEYS);
  }
  
}
