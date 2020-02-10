package edu.sjsu.crypto.ciphersys.classic;

import org.junit.jupiter.api.Test;

import lombok.extern.slf4j.Slf4j;
@Slf4j
class SimpleSubSysTest {

	@Test
	void test() {
		String plaintext = "No Class Cancellation";
		int key = 15;
		SimpleSubSys sys = new SimpleSubSys(key);
		log.info("Ciphertext = [" + sys.encrypt(plaintext)+ "]");
	}
	@Test
	void test2() {
		String ciphertext = "EQ FSEW AK KAVS, A DACW LZAK UDSKK!";
		int key = 44;
		SimpleSubSys sys = new SimpleSubSys(key);
		log.info("Recovered Plaintext = [" + sys.decrypt(ciphertext)+ "]");
	}

}
