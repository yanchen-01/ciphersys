package edu.sjsu.crypto.ciphersys.stream;

import edu.sjsu.yazdankhah.crypto.util.abstracts.PkzipAbs;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.*;
import edu.sjsu.yazdankhah.crypto.util.primitivedatatypes.*;

/**
 * PKZIP cipher system
 * @author Yan Chen
 * Customer: Sida Zhong
 */
public class PkzipSys extends PkzipAbs {
    private Word X, Y, Z;
    private String pass;

    /**
     * Instantiates a new PKZIP cipher system.
     *
     * @param pass the string used to generate the keystream
     */
    public PkzipSys(String pass) {
        pass = ConversionUtil.textToBinStr(pass);
        this.pass = StringUtil.rightTruncRightPadWithZeros(pass, KEY_SIZE_BITS);
    }

    /**
     * Generate one byte of keystream
     * @param word the register for generating the keystream
     * @return one byte of keystream
     */
    @Override
    public UByte generateKey(Word word) {
        Word t = word.or(THREE_WORD).rightHalfAsWord();

        t.multiplyMod2p32M(t.xor(Word.ONE_WORD));
        t.shiftRightM(KEY_GENERATION_SHIFTS);

        return t.byteAt(3);
    }

    /**
     * Update the contents of X, Y, and Z words
     * @param x word X
     * @param y word Y
     * @param z word Z
     * @param p current plaintext byte
     */
    @Override
    public void update(Word x, Word y, Word z, UByte p) {
        CRC(x, p);

        y.addMod2p32M(Word.constructFromUByte(x.byteAt(3)));
        y.multiplyMod2p32M(UPDATE_CONST_WORD);
        y.addMod2p32M(Word.ONE_WORD);

        CRC(z, y.byteAt(0));
    }

    /**
     * Cyclic Redundancy Check (CRC) for error detection
     * in the ZIP compression process.
     *
     * @param V Word V
     * @param b Unsigned Byte b
     */
    @Override
    public void CRC(Word V, UByte b) {
        V.xorM(Word.constructFromUByte(b));

        for (int i = 0; i < CRC_ITERATION; i++) {
            V.shiftRightM(1);
            if (V.toLong() % 2 != 0) V.xorM(CRC_CONST_WORD);
        }
    }

    /**
     * Encrypt the plaintext to cipher in hex
     * @param plaintext the plaintext
     * @return cipher in hex string
     */
    @Override
    public String encrypt(String plaintext) {
        initialize();
        UByte[] plain = ConversionUtil.textToUByteArr(plaintext);
        UByte[] cipher = new UByte[plain.length];

        for (int i = 0; i < plain.length; i++) {
            cipher[i] = plain[i].xor(generateKey(Z));
            update(X, Y, Z, plain[i]);
        }

        return ConversionUtil.ubyteArrToHexStr(cipher);
    }

    /**
     * Decrypt the cipher in hex to plaintext
     * @param cipherHexStr the cipher hex string
     * @return plaintext
     */
    @Override
    public String decrypt(String cipherHexStr) {
        initialize();
        UByte[] plain = ConversionUtil.hexStrToUByteArr(cipherHexStr);

        for (UByte p : plain) {
            p.xorM(generateKey(Z));
            update(X, Y, Z, p);
        }

        return ConversionUtil.ubyteArrToText(plain);
    }

    /**
     * Private helper method to initialize the registers for generating the key
     */
    private void initialize() {
        X = Word.constructFromBinStr(pass.substring(0, 32));
        Y = Word.constructFromBinStr(pass.substring(32, 64));
        Z = Word.constructFromBinStr(pass.substring(64));
    }
}
