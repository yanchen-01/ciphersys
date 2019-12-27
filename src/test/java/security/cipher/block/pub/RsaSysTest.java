package security.cipher.block.pub;

import java.math.BigInteger;

import org.junit.jupiter.api.Test;

import edu.sjsu.security.yazdankhah.cipher.publicKey.rsa.RsaSys;
import lombok.extern.slf4j.Slf4j;


@Slf4j
class RsaSysTest {
  
  @Test
  void test() throws Exception {
    //Stamp's book example: p 121 (97)
    BigInteger p, q, e;
    p = BigInteger.valueOf(11);
    q = BigInteger.valueOf(41);
    e = BigInteger.valueOf(17);
    
    long m = 400;
    log.info("M = [" + m + "]");
    RsaSys sys = new RsaSys(p, q, e);
    
    BigInteger c = sys.encrypt(m);
    
    log.info("C = [" + c + "]");
    log.info("M = [" + sys.decrypt(c) + "]");
    
  }
  
}
