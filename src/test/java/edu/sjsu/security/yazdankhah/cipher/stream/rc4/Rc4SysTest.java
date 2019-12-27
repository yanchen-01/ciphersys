package edu.sjsu.security.yazdankhah.cipher.stream.rc4;

import org.junit.jupiter.api.Test;

import lombok.extern.slf4j.Slf4j;

@Slf4j
class Rc4SysTest {
  
  @Test
  void test() {
    
    String pass = "abcdefghijklm";
    log.info("pass = [" + pass + "]");
    
    Rc4Sys sys = new Rc4Sys(pass);
    
    String plaintext = "An iterated block cipher splits the plaintext into fixed-sized blocks.";
    log.info("plaintext = [" + plaintext + "]");
    
    String cipherHexStr = sys.encrypt(plaintext);
    log.info("cipherHexStr = [" + cipherHexStr + "]");
    
    
 // Receiver
    Rc4Sys sysR = new Rc4Sys(pass);
    String plaintextR = sysR.decrypt(cipherHexStr);
    log.info("plaintextR = [" + plaintextR + "]");
    
    sys.printKeyStreamList(" Encryption keystream");
    sysR.printKeyStreamList(" Decryption keystream");
  }
  
}
