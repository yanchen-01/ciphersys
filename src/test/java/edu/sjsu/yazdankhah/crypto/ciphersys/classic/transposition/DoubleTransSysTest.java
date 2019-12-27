package edu.sjsu.yazdankhah.crypto.ciphersys.classic.transposition;

import org.junit.jupiter.api.Test;

import edu.sjsu.yazdankhah.crypto.ciphersys.classic.transposition.DoubleTransSys;
import edu.sjsu.yazdankhah.crypto.util.ciphersysdatatypes.DoubleTransKey;
import lombok.extern.slf4j.Slf4j;


@Slf4j
class DoubleTransSysTest {
  
  @Test
  void testEncrypt() {
    
 // Sender
    //key
    int row = 3;
    int col = 4;
    int[] rowPermutation = {3,2,1};
    int[] colPermutation = {4,2,1,3};
    DoubleTransKey k = new DoubleTransKey(row, col, rowPermutation, colPermutation);
    
    DoubleTransSys sys = new DoubleTransSys(k);
    sys.printKey();
    
//    String plaintext = "defend the east wall";
    String plaintext = "Although the general knapsack problem is known to be NP-complete, "
      + "there is a special case that can be solved in linear time. A super-increasing "
      + "knapsack is similar to the general knapsack except that, when the weights "
      + "are arranged from least to greatest, each weight is greater than sum of all previous weights.";
    
    log.info("plaintext  = [" + plaintext + "]\n");
    
    String ciphertext = sys.encrypt(plaintext);
    log.info("ciphertext = [" + ciphertext + "]\n");
    
    
    // Receiver
    String plaintextR = sys.decrypt(ciphertext);
    log.info("plaintextR = [" + plaintextR + "]\n");
  }
  
}
