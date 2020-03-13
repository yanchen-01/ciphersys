package edu.sjsu.crypto.ciphersys.block;

import edu.sjsu.yazdankhah.crypto.util.abstracts.TeaAbs;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.*;
import edu.sjsu.yazdankhah.crypto.util.primitivedatatypes.*;
/**
 * TEA cipher system
 * @author Yan Chen
 * Customer: Sida Zhong
 */
public class TeaSys extends TeaAbs {
    private Word[] SK;

    /**
     * Instantiates a new TEA cipher system.
     *
     * @param pass the string used to generate the key
     */
    public TeaSys(String pass) {
        pass = ConversionUtil.textToBinStr(pass);
        pass = StringUtil.rightTruncRightPadWithZeros(pass, KEY_SIZE_BITS);
        SK = ConversionUtil.binStrToWordArr(pass);
    }

    /**
     * Encrypt the plaintext to cipher in hex.
     *
     * @param plaintext the plaintext
     * @return cipher in hex string
     */
    @Override
    public String encrypt(String plaintext) {
        DWord[] textBlock = ConversionUtil.textToDWordArr(plaintext);
        for (int i = 0; i < textBlock.length; i++)
            textBlock[i] = encryptOneBlock(textBlock[i]);
        return ConversionUtil.dwordArrToHexStr(textBlock);
    }

    /**
     * Decrypt the cipher in hex to plaintext.
     *
     * @param ciphertext the cipher hex string
     * @return plaintext
     */
    @Override
    public String decrypt(String ciphertext) {
        DWord[] textBlock = ConversionUtil.hexStrToDWordArr(ciphertext);
        for (int i = 0; i < textBlock.length; i++)
            textBlock[i] = decryptOneBlock(textBlock[i]);
        return ConversionUtil.dwordArrToText(textBlock).trim();
    }

    /**
     * Private helper method to encrypt one block.
     *
     * @param P one block of the plaintext (8 bytes)
     * @return 8-bytes block after encryption
     */
    private DWord encryptOneBlock(DWord P) {
        Word L = P.leftWord();
        Word R = P.rightWord();
        Word sum = Word.ZERO();

        for (int r = 0; r < ROUNDS; r++) {
            sum.addMod2p32M(DELTA_WORD);
            L.addMod2p32M(function(R, sum, 0, 1));
            R.addMod2p32M(function(L, sum, 2, 3));
        }

        return DWord.constructFrom2Words(L, R);
    }

    /**
     * Private helper method to decrypt one block.
     *
     * @param C one block of the ciphertext (8 bytes)
     * @return 8-bytes block after decryption
     */
    private DWord decryptOneBlock(DWord C) {
        Word L = C.leftWord();
        Word R = C.rightWord();
        Word sum = DELTA_WORD.shiftLeft(5);

        for (int r = 0; r < ROUNDS; r++) {
            R.subtractMod2p32M(function(L, sum, 2, 3));
            L.subtractMod2p32M(function(R, sum, 0, 1));
            sum.subtractMod2p32M(DELTA_WORD);
        }

        return DWord.constructFrom2Words(L, R);
    }

    /**
     * Private helper method for encryption/decryption:
     * (in≪4 + SK[i]) ⊕ (in+sum) ⊕ (in≫5 + SK[j])
     *
     * @param in input Word (left half or Right half)
     * @param sum sum in the process of encryption/decryption
     * @param i index of first SK element
     * @param j index of second SK element
     * @return result word
     */
    private Word function(Word in, Word sum, int i, int j) {
        Word temp1 = in.shiftLeft(4).addMod2p32(SK[i]);
        Word temp2 = in.addMod2p32(sum);
        Word temp3 = in.shiftRight(5).addMod2p32(SK[j]);
        return temp1.xor(temp2).xor(temp3);
    }
}