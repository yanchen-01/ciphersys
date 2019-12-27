package edu.sjsu.security.yazdankhah.cipher.stream.pkzip;

import org.junit.jupiter.api.Test;

import edu.sjsu.security.primitivedatatypes.UByte;
import edu.sjsu.security.primitivedatatypes.Word;
import lombok.extern.slf4j.Slf4j;


@Slf4j
class PkZipSysTest {
  
  
  //@Test
  void testCRC() throws Exception {
    
    String valBitStr = "0000_0000_0000_0000_0000_1111_0000_1111";
    Word x = Word.constructFromBinStr(valBitStr);
    x.printAllFormat("= x input");
    
    UByte b = UByte.constructFromBinStr("0000_0001");
    b.printAllFormat("= b input\n");
    
//    Word res = PkZipSys.CRC(x, b);
//    res.printAllFormat("= res\n");
    
    
    x.printAllFormat("= x output");
    b.printAllFormat("= b output");
  }

  
  //@Test
  void testGenerateKey() throws Exception {
    
    String pass = "abcdefghijklm";
    PkZipSys sys = new PkZipSys(pass);
    
    String valBitStr = "0000_0000_0000_0000_0000_1111_0000_1111";
    Word z1 = Word.constructFromBinStr(valBitStr);
    
    UByte kI = sys.generateKey(z1);
    kI.printAllFormat("= kI");
    z1.printAllFormat("= z at the end");
    
  }

  
  @Test
  void testPkZipSys() throws Exception {
    String pass = "abcdefghijklm";
    log.info("pass = [" + pass + "]");
    
    PkZipSys sys = new PkZipSys(pass);
    
    String plaintext = "attackatdawn";
    log.info("plaintext = [" + plaintext + "]");
    
    String ciphertext = sys.encrypt(plaintext);
    log.info("ciphertext = [" + ciphertext + "]");
    
    
    // Receiver
    PkZipSys sysR = new PkZipSys(pass);
    String plaintextR = sysR.decrypt(ciphertext);
    log.info("plaintextR = [" + plaintextR + "]");
    
    sys.printKeyStreamList(" Encryption keystream");
    sysR.printKeyStreamList(" Decryption keystream");
  }
  
}
