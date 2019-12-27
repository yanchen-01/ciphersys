package edu.sjsu.yazdankhah.crypto.ciphersys.classic.shift;


import org.junit.jupiter.api.Test;

import edu.sjsu.yazdankhah.crypto.ciphersys.classic.shift.SimpleSubSys;
import lombok.extern.slf4j.Slf4j;

@Slf4j
class SimpleSubSysTest {
  
  @Test
  void testEncrypt() {
    
    // Sender
    int key = 3;
    
    SimpleSubSys sys = new SimpleSubSys(key);
    sys.printKey();
    
    String plaintext = "defend the east wall of the castle";
//    String plaintext = "Although the general knapsack problem is known to be NP-complete,\r\n" + 
//        "there is a special case that can be solved in linear time. A superincreasing\r\n" + 
//        "knapsack is similar to the general knapsack except that, when the weights\r\n" + 
//        "are arranged from least to greatest, each weight is greater than sum of all\r\n" + 
//        "previous weights.";
    
    log.info("plaintext  = [" + plaintext + "]");
    
    String ciphertext = sys.encrypt(plaintext);
    log.info("ciphertext = [" + ciphertext + "]");
    
    // Receiver
    String plaintextR = sys.decrypt(ciphertext);
    log.info("plaintextR = [" + plaintextR + "]");
  }
  
}
