package edu.sjsu.crypto.ciphersys.classic;

import lombok.extern.slf4j.Slf4j;

@Slf4j
class DoubleTransSysTest {

    @org.junit.jupiter.api.Test
    void decrypt() {
        String ciphertext = "s smani e ym evi ,ol adi  sc ssaliht";
        int[] rowsPerm = { 3, 1, 2, 0 };
        int[] colsPerm = { 2, 1, 0 };
        DoubleTransSys sys = new DoubleTransSys(rowsPerm, colsPerm);
        log.info("Recovered Plaintext = [" + sys.decrypt(ciphertext)+ "]\n");
    }

    @org.junit.jupiter.api.Test
    void encrypt() {
        String plaintext = "Get straight A's";
        int[] rowsPerm = { 3, 1, 2, 0 };
        int[] colsPerm = { 2, 1, 0 };
        DoubleTransSys sys = new DoubleTransSys(rowsPerm, colsPerm);
        log.info("ciphertext = [" + sys.encrypt(plaintext)+ "]\n");
    }
}