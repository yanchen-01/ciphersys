package edu.sjsu.yazdankhah.crypto.ciphersys.block.des;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import edu.sjsu.yazdankhah.crypto.ciphersys.block.des.DesSys;
import edu.sjsu.yazdankhah.crypto.ciphersys.block.feal.FealSys;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.ConversionUtil;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.StringUtil;
import edu.sjsu.yazdankhah.crypto.util.primitivedatatypes.Word;
import edu.sjsu.yazdankhah.crypto.util.shiftregisters.ShiftReg;
import lombok.extern.slf4j.Slf4j;


@Slf4j
class DesSysTest {
  
  @Test
  void test() {
    
    String passText = "0123456789abcdef";
    log.info("passText     = [" + passText + "]");
    
    DesSys sys = new DesSys(passText);
    
    String plaintext = "attack at dawn";
    log.info("plaintext    = [" + plaintext + "]");
    
    String cipherHexStr = sys.encrypt(plaintext);
    log.info("cipherHexStr = [" + cipherHexStr + "]");
    
    // Receiver
    DesSys sysR = new DesSys(passText);
    String plaintextR = sysR.decrypt(cipherHexStr);
    log.info("plaintextR   = [" + plaintextR + "]");
    
    // sys.printSubKeysArray();
  }
  
  
  //@Test
  void F() {
    
    String hexStr = "01234567";
    Word w = Word.constructFromHexStr(hexStr);
    w.printAllFormat("sr32");
    assertEquals("01234567", w.toHexStr());
    
    hexStr = "890123456789";
    ShiftReg k48 = ShiftReg.constructFromHexStr(hexStr);
    k48.printAllFormat("k48");
    assertEquals("890123456789", k48.toHexStr());
    
    Word f = DesSys.F(w, k48);
    f.printAllFormat();
    
  }
  
}