package edu.sjsu.security.yazdankhah.cipher.publicKey.knapsack;

import java.math.BigInteger;

import org.junit.jupiter.api.Test;

import edu.sjsu.security.abstracts.KnapsackAbs;
import edu.sjsu.security.cipherutils.PrintUtil;
import edu.sjsu.security.primitivedatatypes.Bit;
import lombok.extern.slf4j.Slf4j;


@Slf4j
class KnapsackSysTest {
  
  private final static String publicKeyPath = "D:\\dev\\ws\\wsSecurity\\ciphersys\\src\\main\\java\\edu\\sjsu\\"
      + "security\\yazdankhah\\cipher\\publicKey\\knapsack\\publicKey.txt";
  
  private final static String privateKeyPath = "D:\\dev\\ws\\wsSecurity\\ciphersys\\src\\main\\java\\edu\\sjsu\\"
      + "security\\yazdankhah\\cipher\\publicKey\\knapsack\\privateKey.txt";
  
  
  @Test
  void test() {
    String passtext = "0123456789abcdef0123456789abcdef";
    log.info("passtext = [" + passtext + "]");
    
    KnapsackSys sys = new KnapsackSys();
    sys.restorePrivateKey(privateKeyPath);
    sys.restorePublicKey(publicKeyPath);
    
    log.info("Private Key  = [\n" + sys.getPrivateKey() + "\n]\n");
    log.info("Public Key   = [\n" + sys.getPublicKey() + "\n]\n");
    
    
//   String plaintext = "41ea3a0a 94baa940";
   String plaintext = "attack at dawn";
//   String plaintext = "Although the general knapsack problem is known to be NP-complete, "
//       + "there is a special case that can be solved in linear time. A super-increasing "
//       + "knapsack is similar to the general knapsack except that, when the weights "
//       + "are arranged from least to greatest, each weight is greater than sum of all previous weights.";
    
   log.info("plaintext    = [" + plaintext + "]");
   
   String cipherHexStr = sys.encrypt(plaintext, sys.getPublicKey());
   log.info("cipherHexStr = [" + cipherHexStr + "]");
   
   
   // Receiver
   //TeaSys sysR = new TeaSys(passText);
   String plaintextR = sys.decrypt(cipherHexStr, sys.getPrivateKey());
   log.info("plaintextR   = [" + plaintextR + "]");
   
//   sys.printKey();
  }
  
  
  //@Test
  void restoreKeys() {
    
    KnapsackSys sys = new KnapsackSys();
    
    sys.restorePublicKey(publicKeyPath);
    log.info("Restored Public Key   = [\n" + sys.getPublicKey() + "\n]\n");
    
    sys.restorePrivateKey(privateKeyPath);
    log.info("Restored Private Key  = [\n" + sys.getPrivateKey() + "\n]\n");
  }
  
  
  //@Test
  void saveKeys() {
    String passtext = "0123456789abcdef0123456789abcdef";
    log.info("passText = [" + passtext + "]");
    String name = "Ahmad Yazdankhah";
    log.info("name = [" + name + "]");
    
    KnapsackSys sys = new KnapsackSys();
    sys.constructKnapsackKeys(passtext, name);
    
    log.info("Private Key  = [\n" + sys.getPrivateKey() + "\n]\n");
    log.info("Public Key   = [\n" + sys.getPublicKey() + "\n]\n");
    
    sys.savePublicKey(publicKeyPath);
    sys.savePrivateKey(privateKeyPath);
  }
  
  
  //@Test
  void solveSuperIncreasingKnapsackIntVersioin() {
    
    int[] w = {3, 6, 11, 25, 46, 95, 200, 411};
    int sum = 309;
    Bit[] bitArr = KnapsackAbs.solveSuperIncreasingKnapsack(w, sum);
    PrintUtil.printBitArrFormatted(bitArr);
  }
  
  //@Test
  void solveSuperIncreasingKnapsackBigIntVersioin() {
    
    BigInteger[] w = {new BigInteger("3"), new BigInteger("6"), new BigInteger("11"), 
        new BigInteger("25"), new BigInteger("46"), new BigInteger("95"), new BigInteger("200"), 
        new BigInteger("411")};
    BigInteger sum = new BigInteger("309");
    Bit[] bitArr = KnapsackAbs.solveSuperIncreasingKnapsack(w, sum);
    PrintUtil.printBitArrFormatted(bitArr);
  }
  
}
