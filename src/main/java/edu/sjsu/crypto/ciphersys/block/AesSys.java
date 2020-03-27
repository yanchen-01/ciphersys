package edu.sjsu.crypto.ciphersys.block;

import edu.sjsu.yazdankhah.crypto.util.abstracts.AesAbs;
import edu.sjsu.yazdankhah.crypto.util.ciphersysdatatypes.AesState;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.ConversionUtil;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.StringUtil;
import edu.sjsu.yazdankhah.crypto.util.primitivedatatypes.UByte;
import edu.sjsu.yazdankhah.crypto.util.primitivedatatypes.Word;

/**
 * AES cipher system
 *
 * @author Yan Chen
 */
public class AesSys extends AesAbs {
    private AesState[] SK;

    /**
     * Instantiates a new AES cipher system.
     *
     * @param pass the string used to generate the key
     */
    public AesSys(String pass) {
        pass = ConversionUtil.textToBinStr(pass);
        pass = StringUtil.rightTruncRightPadWithZeros(pass, KEY_SIZE_BITS);
        generateSubKeys(AesState.constructFromBinStr(pass));
    }

    /**
     * Encrypt the plaintext to cipher in hex.
     *
     * @param plaintext the plaintext
     * @return cipher in hex string
     */
    @Override
    public String encrypt(String plaintext) {
        AesState[] textBlock = ConversionUtil.textToAesStateArr(plaintext);

        for (int i = 0; i < textBlock.length; i++)
            textBlock[i] = encryptOneBlock(textBlock[i]);

        return ConversionUtil.aesStateArrToHexStr(textBlock);
    }

    /**
     * Decrypt the cipher in hex to plaintext.
     *
     * @param cipherHexStr the cipher hex string
     * @return decrypted plaintext
     */
    @Override
    public String decrypt(String cipherHexStr) {
        AesState[] textBlock = ConversionUtil.hexStrToAesStateArr(cipherHexStr);

        for (int i = 0; i < textBlock.length; i++)
            textBlock[i] = decryptOneBlock(textBlock[i]);

        return ConversionUtil.aesStateArrToText(textBlock).trim();
    }

    /**
     * Private helper method to encrypt one block.
     *
     * @param P one block of the plaintext (4 x 4 byte matrix)
     * @return 4 x 4 byte matrix block after encryption
     */
    private AesState encryptOneBlock(AesState P) {
        P.addRoundKeyM(SK[0]);
        for (int r = 1; r <= ROUNDS; r++) {
            P.byteSubM(SBOX);
            P.shiftRowM();
            if (r != 10) P.mixColumnM(MIX_COLUMN_CONSTANT_STATE);
            P.addRoundKeyM(SK[r]);
        }
        return P;
    }

    /**
     * Private helper method to decrypt one block.
     *
     * @param C one block of the cipher (4 x 4 byte matrix)
     * @return 4 x 4 byte matrix block after decryption
     */
    private AesState decryptOneBlock(AesState C) {
        for (int r = ROUNDS; r > 0; r--) {
            C.addRoundKeyM(SK[r]);
            if (r != 10) C.mixColumnM(INV_MIX_COLUMN_CONSTANT_STATE);
            C.invShiftRowM();
            C.byteSubM(INVERSE_SBOX);
        }
        C.addRoundKeyM(SK[0]);
        return C;
    }

    /**
     * Private helper method to generate sub keys (SK).
     *
     * @param K 4 x 4 byte matrix (from the password)
     */
    private void generateSubKeys(AesState K) {
        SK = new AesState[SUBKEYS_ARRAY_SIZE];
        SK[0] = K;
        for (int r = 1; r <= ROUNDS; r++)
            SK[r] = oneRoundKeyGeneration(SK[r - 1], r);
    }

    /**
     * Private helper method for one round of generating sub keys.
     *
     * @param Q 4 x 4 byte matrix
     * @param r round number
     * @return 4 x 4 byte matrix generated
     */
    private AesState oneRoundKeyGeneration(AesState Q, int r) {
        Word[] WArr = Q.toWordArr();

        WArr[0].xorM(gFunction(WArr[3], r));
        for (int i = 1; i < WArr.length; i++)
            WArr[i].xorM(WArr[i - 1]);

        return AesState.constructFromWordArr(WArr);
    }

    /**
     * Private helper method for the g-function of key Generation.
     *
     * @param W0 4-Byte used for Key generation
     * @param r  round number
     * @return 4-Byte generated
     */
    private Word gFunction(Word W0, int r) {
        Word W1 = W0.rotateLeftBytes();

        UByte[] bytes = W1.toUByteArr();
        for (int i = 0; i < WORD_SIZE_BYTES; i++)
            bytes[i] = SBOX.lookUp(W1.byteAt(i));

        bytes[0].xorM(RC[r - 1]);
        return Word.constructFromUByteArr(bytes);
    }
}