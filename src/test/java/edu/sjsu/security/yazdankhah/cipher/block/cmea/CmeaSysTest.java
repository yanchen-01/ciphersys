package edu.sjsu.security.yazdankhah.cipher.block.cmea;

import org.junit.jupiter.api.Test;

import edu.sjsu.security.cipherutils.StringUtil;
import lombok.extern.slf4j.Slf4j;

@Slf4j
class CmeaSysTest {
  
  @Test
  void test() {
    String pass = "abcdefghijklm";
    log.info("pass = [" + pass + "]");
    
    CmeaSys sys = new CmeaSys(pass);
    
    String plaintext = "attack at dawn";
    log.info("plaintext = [" + plaintext + "]");
    
    String cipherHexStr = sys.encrypt(plaintext);
    log.info("cipherHexStr = [" + cipherHexStr + "]");
    log.info("cipherHexStr = [" + StringUtil.makeFormattedStr(cipherHexStr) + "]");
    
    
 // Receiver
    CmeaSys sysR = new CmeaSys(pass);
    String plaintextR = sysR.decrypt(cipherHexStr);
    log.info("plaintextR = [" + plaintextR + "]");
    
  }
  
}
