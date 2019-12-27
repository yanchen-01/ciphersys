package edu.sjsu.security.yazdankhah.cipher.block.akelarre;

import org.junit.jupiter.api.Test;

import edu.sjsu.security.cipherutils.StringUtil;
import edu.sjsu.security.primitivedatatypes.DByte;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class AkelarreSysTest {
  
  @Test
  void test() {
    
    String passText = "abcdefghijklmnop";
    log.info("passText     = [" + passText + "]");
    
    AkelarreSys sys = new AkelarreSys(passText);
    
    String plaintext = "attack at dawn";
    log.info("plaintext    = [" + plaintext + "]");
    
    String cipherHexStr = sys.encrypt(plaintext);
    log.info("cipherHexStr = [" + cipherHexStr + "]");
    log.info("cipherHexStr = [" + StringUtil.makeFormattedStr(cipherHexStr) + "]");
    
    
 // Receiver
    AkelarreSys sysR = new AkelarreSys(passText);
    String plaintextR = sysR.decrypt(cipherHexStr);
    log.info("plaintextR   = [" + plaintextR + "]");
    
    
    //sys.printKeyStreamArray("Key Expansion");
  }
  
  
  
  //@Test
  void testUi() {
    DByte db0 = DByte.constructFromHexStr("ffff");
    db0.printAllFormat();
    
//    log.info("ui0 = [" + StringUtil.makeFormattedStr(AkelarreSys.ui(db0)) + "]");
    //AkelarreSys.(db0).printAllFormat();
  }


  
}
