package edu.sjsu.yazdankhah.crypto.ciphersys.stream.pkzip;

import java.util.ArrayList;
import java.util.List;

import edu.sjsu.yazdankhah.crypto.util.abstracts.PkzipSysInt;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.ConversionUtil;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.PrintUtil;
import edu.sjsu.yazdankhah.crypto.util.primitivedatatypes.UByte;
import edu.sjsu.yazdankhah.crypto.util.primitivedatatypes.Word;
import lombok.extern.slf4j.Slf4j;


@Slf4j
public class PkZipSys implements PkzipSysInt {
  
  private final List<UByte> keyStream = new ArrayList<>();
  private Word xI, yI, zI;
  
  
  public PkZipSys(String pass) {
    
    String xStr = pass.substring(0, 4);
    String yStr = pass.substring(4, 8);
    String zStr = pass.substring(8, 12);
    
    xI = Word.constructFromHexStr(ConversionUtil.textToHexStr(xStr));
    yI = Word.constructFromHexStr(ConversionUtil.textToHexStr(yStr));
    zI = Word.constructFromHexStr(ConversionUtil.textToHexStr(zStr));
    
    // xI.printAllFormat("= initial xI");
    // yI.printAllFormat("= initial yI");
    // zI.printAllFormat("= initial zI");
    
  }
  
  
  /**
   * Generates one UByte of the key stream. The input word z does not change.
   * 
   * @param z the given word.
   * @return
   * @throws Exception
   */
  @Override
  public UByte generateKey(Word z) throws Exception {
    
    // z.printAllFormat("= input z");
    
    Word tI = z.or(Word.constructFromLong(3L)).rightHalfAsWord(); // bits 16...31
    // tI.printAllFormat("= tI");
    
    // Word tI1 = tI.XOR(Word.constructFromLong(1L));
    // tI1.printAllFormat("= tI1 ");
    
    long tempLong = tI.toLong() * tI.xor(Word.constructFromLong(1L)).toLong();
    
    Word tIM = Word.constructFromLong(tempLong);
    // tIM.printAllFormat("= tI * tI1");
    
    UByte kI = tIM.shiftRightM(8).byteAt(3); // bits 24...31
    // kI.printAllFormat("= kI");
    
    keyStream.add(kI);
    return kI;
  }
  
  
  @Override
  public void update(Word x, Word y, Word z, UByte p) throws Exception {
    
    xI = CRC(x, p);
    // xI.printAllFormat("= xI after update");
    
    long tempLong = (y.toLong() + x.byteAt(3).toLong()) * UPDATE_CONST + 1;
    tempLong = tempLong % (long) Math.pow(2.0, 32);
    yI = Word.constructFromLong(tempLong);
    // yI.printAllFormat("= yI after update");
    
    zI = CRC(z, y.byteAt(0));
    // zI.printAllFormat("= zI after update");
  }
  
  
  @Override
  public Word CRC(Word x, UByte b) throws Exception {
    
    Word xClone = x.clone();
    Word crcConst = Word.constructFromHexStr(CRC_CONST);
    // crcConst.printAllFormat("= crc const\n");
    
    Word bWord = Word.constructFromUByte(b);
    // bWord.printAllFormat("= bWord");
    
    xClone = xClone.xor(bWord);
    // xClone.printAllFormat("= xClone after XOR");
    
    for (int i = 0; i < CRC_ITERATION; i++) {
      if (xClone.toLong() % 2 != 0) { // it's odd
        // xClone.printAllFormat("= xClone");
        // crcConst.printAllFormat("= crc const");
        xClone = xClone.shiftRightM(1).xor(crcConst);
        // xClone.printAllFormat("= xClone odd");
      } else {
        xClone = xClone.shiftRightM(1);
        // xClone.printAllFormat("= xClone even");
      }
    }
    
    return xClone;
  }
  
  
  @Override
  public String encrypt(String plaintext) throws Exception {
    
    UByte[] plainTextArr = ConversionUtil.textToUByteArr(plaintext);
    PrintUtil.printUByteArrFormatHexStr(plainTextArr, "_");
    StringBuilder sb = new StringBuilder();
    
    for (UByte pI : plainTextArr) {
      UByte keyI = generateKey(zI);
      UByte cI = pI.xor(keyI);
      
      sb.append(cI.toHexStr());
      update(xI, yI, zI, pI);
    }
    
    return sb.toString();
  }
  
  
  @Override
  public String decrypt(String ciphertextHex) throws Exception {
    
    UByte[] cipherTextArr = ConversionUtil.hexStrToUByteArr(ciphertextHex);
    
    PrintUtil.printUByteArrFormatHexStr(cipherTextArr, "_");
    StringBuilder sb = new StringBuilder();
    
    for (UByte cI : cipherTextArr) {
      UByte keyI = generateKey(zI);
      UByte pI = cI.xor(keyI);
      
      sb.append(pI.toChar());
      update(xI, yI, zI, pI);
    }
    
    return sb.toString();
  }
  
  
  @Override
  public void printKeyStreamList(String msg) {
    log.info(keyStream.toString() + " " + msg);
  }
  
}
