package edu.sjsu.security.yazdankhah.cipher.block.feal;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import edu.sjsu.security.cipherutils.StringUtil;
import edu.sjsu.security.primitivedatatypes.DByte;
import edu.sjsu.security.primitivedatatypes.UByte;
import edu.sjsu.security.primitivedatatypes.Word;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class FealSysTest {
  
  @Test
  void test() {
    
    String passText = "0123456789abcdef";
    log.info("passText     = [" + passText + "]");
    
    FealSys sys = new FealSys(passText);
    
    String plaintext = "attack at dawn";
    //String plaintext = "0000000000000000";
    log.info("plaintext    = [" + plaintext + "]");
    
    String cipherHexStr = sys.encrypt(plaintext);
    log.info("cipherHexStr = [" + cipherHexStr + "]");
    log.info("cipherHexStr = [" + StringUtil.makeFormattedStr(cipherHexStr) + "]");
    
    
 // Receiver
    FealSys sysR = new FealSys(passText);
    String plaintextR = sysR.decrypt(cipherHexStr);
    log.info("plaintextR   = [" + plaintextR + "]");
    
    
    //sys.printKeyStreamArray("Key Expansion");
  }
  
  
  
  //@Test
  void Fk() {
    
    Word x = Word.constructFromHexStr("01234567");
    x.printAllFormat("First Arg 01234567");
    
    Word y = Word.constructFromHexStr("89abcdef");
    y.printAllFormat("Second Arg 89abcdef");
    
    Word z = FealSys.Fk(x, y);
    z.printAllFormat("Result of FK");
    
  }

  //@Test
  void F() {
    
    Word x = Word.constructFromHexStr("12345678");
    x.printAllFormat("First Arg 12345678");
    DByte y = DByte.constructFromHexStr("9001");
    y.printAllFormat("Second Arg 9001");
    
    Word z = FealSys.F(x, y);
    z.printAllFormat("Result of F");
  }

  //@Test
  void S() {
    UByte a = UByte.constructFromBinStr("1000_0010");
    a.printAllFormat();

    UByte b = UByte.constructFromBinStr("1001_0100");
    b.printAllFormat();

    UByte ub = FealSys.S(a, b, 1);
    assertEquals("5c", ub.toHexStr());
    
    ub.printAllFormat();
  }
  
}
