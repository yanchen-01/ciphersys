package edu.sjsu.security.yazdankhah.cipher.block.tea;

import org.junit.jupiter.api.Test;

import edu.sjsu.security.primitivedatatypes.UByte;
import edu.sjsu.security.primitivedatatypes.Word;
import lombok.extern.slf4j.Slf4j;


@Slf4j
class TeaSysTest {
  
   @Test
  void test() {
//   String passText = "0123456789abcdef0123456789abcdef";
    String passText = "This is a key!";
    log.info("passText     = [" + passText + "]");
    
    TeaSys sys = new TeaSys(passText);
    
    String plaintext = "attack at dawn";
//    String plaintext = "41ea3a0a 94baa940";
//    String plaintext = "Although the general knapsack problem is known to be NP-complete, "
//        + "there is a special case that can be solved in linear time. A super-increasing "
//        + "knapsack is similar to the general knapsack except that, when the weights "
//        + "are arranged from least to greatest, each weight is greater than sum of all previous weights.";

    
    log.info("plaintext    = [" + plaintext + "]");
    
    String cipherHexStr = sys.encrypt(plaintext);
    log.info("cipherHexStr = [" + cipherHexStr + "]");
    
    // Receiver
    //TeaSys sysR = new TeaSys(passText);
    String plaintextR = sys.decrypt(cipherHexStr);
    log.info("plaintextR   = [" + plaintextR + "]");
    
    sys.printSubKeysArray();
  }
  
  
  //@Test
  void myTests() {
    Word w0 = Word.constructFromHexStr("01020304");
    w0.printAllFormat("w0");
    
    UByte ub1 = w0.byteAt(0).notM();
    w0.printAllFormat("w0 after some changes");
  }
  
}
