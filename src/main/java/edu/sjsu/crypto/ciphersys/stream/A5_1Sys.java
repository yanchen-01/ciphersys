package edu.sjsu.crypto.ciphersys.stream;

import edu.sjsu.yazdankhah.crypto.util.abstracts.A5_1Abs;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.*;
import edu.sjsu.yazdankhah.crypto.util.primitivedatatypes.Bit;
import edu.sjsu.yazdankhah.crypto.util.shiftregisters.LFSR;

/**
 * A5/1 cipher system.
 *
 * @author Yan Chen
 * customer: Sida Zhong
 */
public class A5_1Sys extends A5_1Abs {
    /* registers for key generation*/
    private LFSR X, Y, Z;

    /**
     * Instantiates a new A5/1 cipher system.
     *
     * @param pass the string used to generate keystream
     */
    public A5_1Sys(String pass) {
        pass = ConversionUtil.textToBinStr(pass);
        pass = StringUtil.rightTruncRightPadWithZeros(pass,64);

        int y = X_REG_SIZE_BITS + Y_REG_SIZE_BITS;

        X = LFSR.constructFromBinStr(pass.substring(0, X_REG_SIZE_BITS), X_TAPS);
        Y = LFSR.constructFromBinStr(pass.substring(X_REG_SIZE_BITS, y), Y_TAPS);
        Z = LFSR.constructFromBinStr(pass.substring(y, 64), Z_TAPS);
    }

    /**
     * Generate one bit of keystream
     * @return bit of keystream
     */
    @Override
    public Bit generateKey() {
        Bit Gx = Bit.zero();
        Bit Gy = Bit.zero();
        Bit Gz = Bit.zero();

        Bit[] ms = {X.bitAt(8), Y.bitAt(10), Z.bitAt(10)};
        Bit m = Function.maj(ms);
        if (m.equal(X.bitAt(8))) Gx = X.stepM();
        if (m.equal(Y.bitAt(10))) Gy = Y.stepM();
        if (m.equal(Z.bitAt(10))) Gz = Z.stepM();

        return Gx.xor(Gy).xor(Gz);
    }

    /**
     * Encrypt a plaintext.
     * @param plaintext
     * @return ciphertext in hex string
     */
    @Override
    public String encrypt(String plaintext) {
        Bit[] ciphertext = ConversionUtil.textToBitArr(plaintext);

        for (int i = 0; i < ciphertext.length; i++) {
            ciphertext[i] = ciphertext[i].xor(generateKey());
        }

        return ConversionUtil.bitArrToHexStr(ciphertext);
    }

    /**
     * Decrypted a ciphertext (in hex string)
     * @param cipherHexStr the cipher hex string
     * @return plaintext
     */
    @Override
    public String decrypt(String cipherHexStr) {
        cipherHexStr = ConversionUtil.hexStrToText(cipherHexStr);
        Bit[] plaintext = ConversionUtil.textToBitArr(cipherHexStr);

        for (int i = 0; i < plaintext.length; i++) {
            plaintext[i] = plaintext[i].xor(generateKey());
        }

        return ConversionUtil.bitArrToText(plaintext);
    }

}
