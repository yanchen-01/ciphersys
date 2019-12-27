package edu.sjsu.security.yazdankhah.cipher.stream.a5_1;

import org.junit.jupiter.api.Test;

import lombok.extern.slf4j.Slf4j;

@Slf4j
class A5_1SysTest {
  
  @Test
  void test() {
    String pass = "abcdefghijklm";
    log.info("pass = [" + pass + "]");
    
    A5_1Sys sys = new A5_1Sys(pass);
    
    String plaintext = "An iterated block cipher splits the plaintext into fixed-sized blocks.";
    log.info("plaintext = [" + plaintext + "]");
    
    String cipherHexStr = sys.encrypt(plaintext);
    log.info("cipherHexStr = [" + cipherHexStr + "]");
    
    
 // Receiver
    A5_1Sys sysR = new A5_1Sys(pass);
    String plaintextR = sysR.decrypt(cipherHexStr);
    log.info("plaintextR = [" + plaintextR + "]");
    
    sys.printKeyStreamList(" Encryption keystream");
    sysR.printKeyStreamList(" Decryption keystream");
  }
  
}
