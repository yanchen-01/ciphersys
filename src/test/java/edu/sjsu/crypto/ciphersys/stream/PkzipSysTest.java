package edu.sjsu.crypto.ciphersys.stream;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
@Slf4j
class PkzipSysTest {

    @Test
    void encrypt() {
        String plaintext = "defend the east wall!";
        String pass = "GoToHell#007";
        PkzipSys sys = new PkzipSys (pass);
        log.info("ciphertext = [" + sys.encrypt(plaintext)+ "]");
        log.info("ciphertext = [" + sys.encrypt(plaintext)+ "]");
    }

    @Test
    void decrypt() {
        String ciphertext = "1f63ddbf86138a442cd1d6ba4a91a8596bca1090a2";
        String pass = "GoToHell#007";
        PkzipSys sysR = new PkzipSys (pass);
        log.info("Recovered Plaintext = [" + sysR.decrypt(ciphertext)+ "]");
        log.info("Recovered Plaintext = [" + sysR.decrypt(ciphertext)+ "]");
    }
}