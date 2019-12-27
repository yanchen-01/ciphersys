package edu.sjsu.yazdankhah.crypto.ciphersys.publicKey.rsa;

import java.math.BigInteger;


public class RsaSys {
  
  private BigInteger e, d, N;
  
  
  public RsaSys(BigInteger p, BigInteger q, BigInteger e)  {
    
    this.N = p.multiply(q);
    System.out.println("N = [" + N + "]");
    
    this.e = e;
    System.out.println("e = [" + e + "]");
    
    BigInteger pqMinus1 = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
    this.d = e.modInverse(pqMinus1);
    System.out.println("d = [" + d + "]");
    
  }
  
  
  public BigInteger encrypt(long m)  {
    
    BigInteger M = BigInteger.valueOf(m);
    
    //if (M.compareTo(N) > 0) throw new Exception("Message is larger than N.");
    
    return M.modPow(e, N);
  }
  
  
  public BigInteger decrypt(BigInteger C) {
    
    //if (C.compareTo(N) > 0) throw new Exception("Cipher is larger than N.");
    
    return C.modPow(d, N);
  }
  
}
