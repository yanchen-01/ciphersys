package edu.sjsu.crypto.ciphersys.classic;

import static org.junit.jupiter.api.Assertions.*;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
@Slf4j
class HelloWorldTest {

	@Test
	void test() {
		HelloWorld.greeting();
	}
	
	@Test
	void testUsingCryptoUtil1() {
		HelloWorld.usingCryptoUtil1();
	}
	@Test
	void testUsingCryptoUtil2() {
		HelloWorld.usingCryptoUtil2();
	}
	
	@Test
	void testUsingUtil3() {
		HelloWorld.usingUtil3();
	}

}
