package edu.sjsu.security.yazdankhah.cipher.block.aes;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import edu.sjsu.security.primitivedatatypes.UByte;
import edu.sjsu.security.primitivedatatypes.Word;
import lombok.extern.slf4j.Slf4j;


@Slf4j
class AesSysTest {
  
  @Test
  void test() {
    
//    String passText = "0f1571c947d9e8590cb7add6af7f6798";
    String passText = "This is a key!";
    log.info("passText     = [" + passText + "]");
    
    AesSys sys = new AesSys(passText);
    
    String plaintext = "attack at dawn";
//    String plaintext = "0123456789abcdeffedcba9876543210";
    log.info("plaintext    = [" + plaintext + "]");
    
    String cipherHexStr = sys.encrypt(plaintext);
    log.info("cipherHexStr = [" + cipherHexStr + "]");
    
    // Receiver
    AesSys sysR = new AesSys(passText);
    String plaintextR = sysR.decrypt(cipherHexStr);
    log.info("plaintextR   = [" + plaintextR + "]");
    
    //sys.printSubKeysArray();
  }
  
  
  //@Test
  void g() {
    
    String hexStr0 = "00 0f f0 ff";
    Word w0 = Word.constructFromHexStr(hexStr0);
    w0.printHexStrFormatted("w0");
    
    w0 = AesSys.g(w0, 0);
    w0.printHexStrFormatted("w0 after applying g-function");
    
    assertEquals("778c1663", w0.toHexStr());
  }
  
  
  
  
  //@Test
  /**
   * Verifies all elements of SBox and SBox-Inverse to be inverse of each other.
   * To run this test, you'd need to uncomment two required methods in AesSys.
   */
  void lookupTable() {
    
    for (int i=0; i<256; i++) {
      
//      UByte ub0 = UByte.constructFromInteger(i);
//      UByte ub1 = AesSys.sboxLookup(ub0);
//      //ub0.printAllFormat();
//      
//      UByte ub2 = AesSys.sboxInverseLookup(ub1);
//      //ub1.printAllFormat();
//      assertEquals(ub2.toHexStr(), ub0.toHexStr());
      log.info("i = " + i + " OK");
    }
    
    
  }
  
}
