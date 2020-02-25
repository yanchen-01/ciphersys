package edu.sjsu.crypto.ciphersys.stream;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
@Slf4j
class A5_1SysTest {

    @Test
    void encrypt() {
        String plaintext = "defend the east wall!";
        String pass = "1";
        A5_1Sys sys = new A5_1Sys (pass);
        log.info("ciphertext = [" + sys.encrypt(plaintext)+ "]");
        log.info("ciphertext = [" + sys.encrypt(plaintext)+ "]");
        log.info("Recovered Plaintext = [" + sys.decrypt(sys.encrypt(plaintext))+ "]");
        log.info("ciphertext = [" + sys.encrypt(plaintext)+ "]");
        log.info("Recovered Plaintext = [" + sys.decrypt(sys.encrypt(plaintext))+ "]");
    }

    @Test
    void decrypt() {
        String ciphertext = "4d79206e616d6520697320736964612c2049206c696b65207468697320636c61737321";

        String pass = "1";
        A5_1Sys sys = new A5_1Sys (pass);
        log.info("Recovered Plaintext = [" + sys.decrypt(ciphertext)+ "]");
    }
}