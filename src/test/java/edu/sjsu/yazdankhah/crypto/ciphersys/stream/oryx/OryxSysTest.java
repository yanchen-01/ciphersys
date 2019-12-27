package edu.sjsu.yazdankhah.crypto.ciphersys.stream.oryx;

import org.junit.jupiter.api.Test;

import edu.sjsu.yazdankhah.crypto.ciphersys.stream.oryx.OryxSys;
import lombok.extern.slf4j.Slf4j;

@Slf4j
class OryxSysTest {
  
  @Test
  void test() {
    String pass = "abcdefghijklm";
    log.info("pass = [" + pass + "]");
    
    OryxSys sys = new OryxSys(pass);
    
    String plaintext = "attackatdawn";
    log.info("plaintext = [" + plaintext + "]");
    
    String ciphertext = sys.encrypt(plaintext);
    log.info("ciphertext = [" + ciphertext + "]");
    
    
    // Receiver
    OryxSys sysR = new OryxSys(pass);
    String plaintextR = sysR.decrypt(ciphertext);
    log.info("plaintextR = [" + plaintextR + "]");
    
    sys.printKeyStreamList(" Encryption keystream");
    sysR.printKeyStreamList(" Decryption keystream");
  }
  
}
