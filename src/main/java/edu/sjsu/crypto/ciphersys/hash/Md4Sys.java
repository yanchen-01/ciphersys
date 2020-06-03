package edu.sjsu.crypto.ciphersys.hash;

import edu.sjsu.yazdankhah.crypto.util.abstracts.Md4Abs;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.ConversionUtil;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.GeneralUtil;
import edu.sjsu.yazdankhah.crypto.util.primitivedatatypes.Word;

/**
 * MD4 cipher system.
 *
 * @author Yan Chen
 */
public class Md4Sys extends Md4Abs {
    private final Word[] ABCD_INIT;
    private Word[] ABCD;

    /**
     * Instantiates a new MD4 cipher system.
     */
    public Md4Sys() {
        ABCD_INIT = new Word[]{A_INIT, B_INIT, C_INIT, D_INIT};
    }

    /**
     * Applies MD4 algorithm on a plaintext.
     *
     * @param plaintext the plaintext
     * @return the digest (128-bit hex string)
     */
    @Override
    public String MD4(String plaintext) {
        ABCD = ABCD_INIT.clone();
        String Mb = ConversionUtil.textToBinStr(plaintext);
        String MbB = md4Padding(Mb);

        String L = md4SizeToBinStrLittleEndian(Mb.length());

        Word[] msgArr = ConversionUtil.binStrToWordArrLittleEndian(MbB);
        Word[] sizeArr = ConversionUtil.binStrToWordArr(L);
        Word[] M = GeneralUtil.appendWordArrs(msgArr, sizeArr);

        Word[][] X = ConversionUtil.wordArrToWordMatrix(M, MD4_BLOCK_SIZE_WORDS);

        for (Word[] x : X) hashOneBlock(x);

        for (Word w : ABCD) w.toLittleEndianFormatM();

        return ConversionUtil.wordArrToHexStr(ABCD);
    }

    /**
     * Private helper method to hash one block.
     *
     * @param X block to hash
     */
    private void hashOneBlock(Word[] X) {
        Word[] AABBCCDD = ABCD.clone();

        for (int i = 0; i < 3; i++)
            round(i, X);

        for (int i = 0; i < ABCD.length; i++)
            ABCD[i] = ABCD[i].addMod2p32(AABBCCDD[i]);
    }

    /**
     * Private helper method for a round.
     *
     * @param r round number
     * @param X block to hash
     */
    private void round(int r, Word[] X) {
        for (int j = 0; j < MD4_BLOCK_SIZE_WORDS; j++) {
            Word[] clone = ABCD.clone();
            for (int i = 0; i < clone.length; i++) {
                if (i != 1 && i != 3)
                    ABCD[i] = clone[3 - i];
                else if (i == 3)
                    ABCD[i] = clone[2];
                else {
                    Word temp = func(r, clone[1], clone[2], clone[3]);
                    temp = clone[0].addMod2p32(temp);
                    Word per = X[PERMUTATION[r][j]].addMod2p32(K[r]);
                    ABCD[i] = temp.addMod2p32(per).rotateLeft(ROTATE[r][j]);
                }
            }
        }
    }
}