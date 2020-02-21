package edu.sjsu.crypto.ciphersys.stream;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
@Slf4j
class A5_1SysTest {

    @Test
    void encrypt() {
        String plaintext = "defend the east wall!";
        String pass = "GoToHell#007";
        A5_1Sys sys = new A5_1Sys (pass);
        log.info("ciphertext = [" + sys.encrypt(plaintext)+ "]");
        log.info("ciphertext = [" + sys.encrypt(plaintext)+ "]");
        log.info("Recovered Plaintext = [" + sys.decrypt(sys.encrypt(plaintext))+ "]");
        log.info("ciphertext = [" + sys.encrypt(plaintext)+ "]");
        log.info("Recovered Plaintext = [" + sys.decrypt(sys.encrypt(plaintext))+ "]");
    }

    @Test
    void decrypt() {
        String ciphertext = "770c48ba9770f1d3139236d3b3442a75ca51e82ba63e6346f14011a9464d076547f18362e5";
        String pass =  "NoDayOff" ;
        A5_1Sys sys = new A5_1Sys (pass);
        log.info("Recovered Plaintext = [" + sys.decrypt(ciphertext)+ "]");
    }
}