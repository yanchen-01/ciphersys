package edu.sjsu.crypto.ciphersys.classic;

import edu.sjsu.yazdankhah.crypto.util.cipherutils.ConversionUtil;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.PrintUtil;
import edu.sjsu.yazdankhah.crypto.util.primitivedatatypes.Word;
import lombok.extern.slf4j.Slf4j;

/**
 * This is a Hello Word class for Cipher Systems project.
 *
 * @author ahmad
 */
@Slf4j
public class HelloWorld {

	/**
	 * Greeting.
	 */
	public static void greeting() {
    log.info("Hello World!");
  }

	/**
	 * Using crypto util 1.
	 */
	public static void usingCryptoUtil1() {
	  String text = "attack";
	  String binStr = ConversionUtil.textToBinStr(text);
	  
	  PrintUtil.printStrFormatted(binStr, "Binary string 1");
  }

	/**
	 * Using crypto util 2.
	 */
	public static void usingCryptoUtil2() {
	  String text = "attack";
	  String binStr = ConversionUtil.textToBinStr(text);
	  
	  PrintUtil.putStrInBox(binStr, "This is the binary string in box!");
  }

	/**
	 * Using util 3.
	 */
	public static void usingUtil3(){
	  Word wo = Word.constructFromHexStr("BCA017");
	  wo.printBinStr();
	  }
}
