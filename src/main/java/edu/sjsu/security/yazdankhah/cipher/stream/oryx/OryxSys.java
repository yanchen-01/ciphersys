package edu.sjsu.security.yazdankhah.cipher.stream.oryx;

import java.util.ArrayList;
import java.util.List;

import edu.sjsu.security.abstracts.OryxSysInt;
import edu.sjsu.security.cipherutils.ConversionUtil;
import edu.sjsu.security.cipherutils.PrintUtil;
import edu.sjsu.security.primitivedatatypes.Bit;
import edu.sjsu.security.primitivedatatypes.UByte;
import edu.sjsu.security.shiftregisters.LFSR;
import lombok.extern.slf4j.Slf4j;


@Slf4j
public class OryxSys implements OryxSysInt  {
  
  private final List<UByte> keyStream = new ArrayList<>();
  private LFSR x, a, b;
  
  
  public OryxSys(String pass) {
    
    String xStr = pass.substring(0, 4);
    String aStr = pass.substring(4, 8);
    String bStr = pass.substring(8, 12);
    
    x = LFSR.constructFromHexStr(ConversionUtil.textToHexStr(xStr), X_TAPS);
    a = LFSR.constructFromHexStr(ConversionUtil.textToHexStr(aStr), A0_TAPS);
    b = LFSR.constructFromHexStr(ConversionUtil.textToHexStr(bStr), B_TAPS);
    
//    x.printAllFormat("x");   x.printTaps("x");
//    a.printAllFormat("a");   a.printTaps("a");
//    b.printAllFormat("b");   b.printTaps("b");
  }
  
  
  /**
   * Generates one UByte of the key stream. The input word z does not change.
   * 
   * @return one UByte of the generated key
   */
  public UByte generateKey() {
    
    x.stepM();
    Bit x26 = x.bitAt(26); //look at the algorithm for these numbers
    Bit x29 = x.bitAt(29);
    
    if (x29.isZero()) {
      a.setTaps(A0_TAPS);
    } else {
      a.setTaps(A1_TAPS);
    }
    a.stepM();
    
    if (x26.isOne()) {
      b.stepM();
    } 
    b.stepM();
    
    int kInt = (x.byteAt(24).toInteger() + a.byteAt(24).toInteger() + b.byteAt(24).toInteger())%256;
    UByte kI = UByte.constructFromInteger(kInt);
    keyStream.add(kI);
    
    return kI;
  }
  
  
  public String encrypt(String plaintext) {
    
    UByte[] plainTextArr = ConversionUtil.textToUByteArr(plaintext);
    PrintUtil.printUByteArrFormatHexStr(plainTextArr, "_");
    StringBuilder sb = new StringBuilder();
    
    for (UByte pI : plainTextArr) {
      UByte keyI = generateKey();
      UByte cI = pI.xor(keyI);
      
      sb.append(cI.toHexStr());
    }
    
    return sb.toString();
  }
  
  
  public String decrypt(String ciphertextHex) {
    
    UByte[] cipherTextArr = ConversionUtil.hexStrToUByteArr(ciphertextHex);
    
    PrintUtil.printUByteArrFormatHexStr(cipherTextArr, "_");
    StringBuilder sb = new StringBuilder();
    
    for (UByte cI : cipherTextArr) {
      UByte keyI = generateKey();
      UByte pI = cI.xor(keyI);
      
      sb.append(pI.toChar());
    }
    
    return sb.toString();
  }
  
  
  public void printKeyStreamList(String msg) {
    log.info(keyStream.toString() + " " + msg);
  }
  
}
