package edu.sjsu.crypto.ciphersys.block;

import edu.sjsu.yazdankhah.crypto.util.abstracts.CmeaAbs;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.*;
import edu.sjsu.yazdankhah.crypto.util.primitivedatatypes.*;
/**
 * CEMA cipher system
 * @author Yan Chen
 * Customer: Sida Zhong
 */
public class CmeaSys extends CmeaAbs {

    UByte[] k;

    /**
     * Instantiates a new CMEA cipher system.
     *
     * @param pass the string used to generate the key
     */
    public CmeaSys(String pass) {
        pass = StringUtil.rightTruncRightPadWithZeros(pass, 8);
        this.k = ConversionUtil.textToUByteArr(pass);
    }

    /**
     * Encrypt the plaintext to cipher in hex.
     * @param plaintext the plaintext
     * @return cipher in hex string
     */
    @Override
    public String encrypt(String plaintext) {
        Word[] PtextBlock = ConversionUtil.textToWordArr(plaintext);
        int n = PtextBlock.length;
        Word[] CtextBlock = new Word[n];
        for (int i = 0; i < n; i++)
            CtextBlock[i] = encryptOneBlock(PtextBlock[i]);
        return ConversionUtil.wordArrToHexStr(CtextBlock);
    }

    /**
     * Decrypt the cipher in hex to plaintext.
     * @param ciphertext the cipher hex string
     * @return plaintext
     */
    @Override
    public String decrypt(String ciphertext) {
        Word CtextBlock[] = ConversionUtil.hexStrToWordArr(ciphertext);
        int n = CtextBlock.length;
        Word[] PtextBlock = new Word[n];
        for (int i = 0; i < n; i++)
            PtextBlock[i] = encryptOneBlock(CtextBlock[i]);
        return ConversionUtil.wordArrToText(PtextBlock).trim();
    }

    /**
     * Private helper method to encrypt/decrypt one block.
     * @param block one block of the plaintext/ciphertext (4 bytes)
     * @return 4-bytes block after encryption/decryption
     */
    private Word encryptOneBlock(Word block) {
        UByte[] pM = block.toUByteArr();
        round_1(pM);
        round_2(pM);
        UByte[] c = round_3(pM);
        return Word.constructFromUByteArr(c);
    }

    /**
     * Private helper method for the 1st round of encryption/decryption.
     * @param pM array of plaintext/ciphertext blocks (mutable)
     */
    private void round_1(UByte[] pM) {
        UByte z = UByte.ZERO();
        for (int i = 0; i < pM.length; i++) {
            pM[i].addMod256M(T(z.xor(UByte.constructFromInteger(i))));
            z.addMod256M(pM[i]);
        }
    }

    /**
     * Private helper method for the 2nd round of encryption/decryption.
     * @param pM array of plaintext/ciphertext blocks (mutable)
     */
    private void round_2(UByte[] pM) {
        int n = pM.length;
        int h = (int) Math.floor(n / 2.0);
        for (int i = 0; i < h; i++) {
            UByte t = pM[n - 1 - i].or(UByte.ONE());
            pM[i].xorM(t);
        }
    }

    /**
     * Private helper method for the 3rd round of encryption/decryption.
     * @param pM array of plaintext/ciphertext blocks (mutable)
     * @return one block of ciphertext/plaintext
     */
    private UByte[] round_3(UByte[] pM) {
        UByte z = UByte.ZERO();
        int n = pM.length;
        UByte[] c = new UByte[n];
        for (int i = 0; i < n; i++) {
            UByte temp = T(z.xor(UByte.constructFromInteger(i)));
            z.addMod256M(pM[i]);
            c[i] = pM[i].subtractMod256(temp);
        }
        return c;
    }

    /**
     * Private helper method for T function which involves Cave Table
     * @param x unsigned byte
     * @return unsigned byte after several xors and lookups.
     */
    private UByte T(UByte x) {
        UByte q = CAVE_LOOKUP.lookUp(x.xor(k[0]).addMod256(k[1])).addMod256(x);
        UByte r = CAVE_LOOKUP.lookUp(q.xor(k[2]).addMod256(k[3])).addMod256(x);
        UByte s = CAVE_LOOKUP.lookUp(r.xor(k[4]).addMod256(k[5])).addMod256(x);
        return CAVE_LOOKUP.lookUp(s.xor(k[6]).addMod256(k[7])).addMod256(x);
    }

}