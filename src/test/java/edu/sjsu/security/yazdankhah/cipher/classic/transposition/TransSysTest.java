package edu.sjsu.security.yazdankhah.cipher.classic.transposition;

import org.junit.jupiter.api.Test;

import lombok.extern.slf4j.Slf4j;

@Slf4j
class TransSysTest {
  
  @Test
  void test() {
    // Sender
    
    int[] key = {3, 2, 0, 1};
    
    TransSys sys = new TransSys(key);
    sys.printKey();
    
//     String plaintext = "defend the east wall";
    String plaintext = "Although the general knapsack problem is known to be NP-complete, "
        + "there is a special case that can be solved in linear time. A super-increasing "
        + "knapsack is similar to the general knapsack except that, when the weights "
        + "are arranged from least to greatest, each weight is greater than sum of all previous weights.";
    
    log.info("plaintext  = [" + plaintext + "]");
    
    String ciphertext = sys.encrypt(plaintext);
    log.info("ciphertext = [" + ciphertext + "]");
    
    // Receiver
    String plaintextR = sys.decrypt(ciphertext);
    log.info("plaintextR = [" + plaintextR + "]");
    
  }
  
}
