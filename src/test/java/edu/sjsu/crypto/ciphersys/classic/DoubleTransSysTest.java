package edu.sjsu.crypto.ciphersys.classic;

import lombok.extern.slf4j.Slf4j;

@Slf4j
class DoubleTransSysTest {

    @org.junit.jupiter.api.Test
    void decrypt() {
        String ciphertext = " EEHFEED TDN    T SALLAW";
        int[] rowsPerm = { 2, 0, 1 };
        int[] colsPerm = { 3, 2, 0, 1 };
        DoubleTransSys sys = new DoubleTransSys(rowsPerm, colsPerm);
        log.info("Recovered Plaintext = [" + sys.decrypt(ciphertext)+ "]\n");
    }

    @org.junit.jupiter.api.Test
    void encrypt() {
        String plaintext = "defend the east wall";
        int[] rowsPerm = { 2, 0, 1 };
        int[] colsPerm = { 3, 2, 0, 1 };
        DoubleTransSys sys = new DoubleTransSys(rowsPerm, colsPerm);
        log.info("ciphertext = [" + sys.encrypt(plaintext)+ "]\n");
    }
}