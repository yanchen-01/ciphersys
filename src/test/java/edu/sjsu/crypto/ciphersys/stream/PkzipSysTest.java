package edu.sjsu.crypto.ciphersys.stream;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
@Slf4j
class PkzipSysTest {

    @Test
    void encrypt() {
        String plaintext = "2019-nCoV";
        String pass = "CDC";
        PkzipSys sys = new PkzipSys (pass);
        log.info("ciphertext = [" + sys.encrypt(plaintext)+ "]");
        log.info("ciphertext = [" + sys.encrypt(plaintext)+ "]");
    }

    @Test
    void decrypt() {
        String pass = "sida";
        String ciphertext = "53d730e57479c33bb121502971868a205aa3bcfd34";
        PkzipSys sysR = new PkzipSys (pass);
        log.info("Recovered Plaintext = [" + sysR.decrypt(ciphertext)+ "]");
        log.info("Recovered Plaintext = [" + sysR.decrypt(ciphertext)+ "]");
    }
}