package edu.sjsu.crypto.ciphersys.publicKey;

import edu.sjsu.yazdankhah.crypto.util.abstracts.KnapsackAbs;
import edu.sjsu.yazdankhah.crypto.util.ciphersysdatatypes.*;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.*;
import edu.sjsu.yazdankhah.crypto.util.primitivedatatypes.Bit;
import edu.sjsu.yazdankhah.crypto.util.primitivedatatypes.Word;

import java.math.BigInteger;
import java.util.Random;

import lombok.Getter;

@Getter
/**
 * Knapsack cipher system.
 * @author Yan Chen
 * Customer: Sida Zhong
 */
public class KnapsackSys extends KnapsackAbs {
    private KnapsackPrivateKey privateKey;
    private KnapsackPublicKey publicKey;

    /**
     * Instantiates a new Knapsack cipher system.
     */
    public KnapsackSys() {
        privateKey = new KnapsackPrivateKey(null, null, null);
        publicKey = new KnapsackPublicKey(null, null);
    }

    /**
     * Encrypt the plaintext to cipher in hex using the public key.
     *
     * @param plaintext the plaintext
     * @param publicKey the public key
     * @return cipher in hex string
     */
    @Override
    public String encrypt(String plaintext, KnapsackPublicKey publicKey) {
        Word[] pTextBlocks = ConversionUtil.textToWordArr(plaintext);
        BigInteger[] cTextBlocks = new BigInteger[pTextBlocks.length];

        for (int i = 0; i < pTextBlocks.length; i++)
            cTextBlocks[i] = encryptOneBlock(pTextBlocks[i], publicKey.getWp());

        return ConversionUtil.bigIntegerArrToHexStr(cTextBlocks, CIPHER_BLOCK_SIZE_BITS);
    }

    /**
     * Decrypt the cipher in hex to plaintext using the private key.
     *
     * @param ciphertext the cipher hex string
     * @param privateKey the private key
     * @return plaintext
     */
    @Override
    public String decrypt(String ciphertext, KnapsackPrivateKey privateKey) {
        BigInteger[] cTextBlocks = ConversionUtil.hexStrToBigIntegerArr(ciphertext, CIPHER_BLOCK_SIZE_BITS);
        StringBuilder result = new StringBuilder();

        BigInteger m = privateKey.getM();
        BigInteger p = privateKey.getP();

        for (int i = 0; i < cTextBlocks.length; i++) {
            BigInteger sum = cTextBlocks[i].multiply(m.modInverse(p)).mod(p);
            Bit[] bits = solveSuperIncreasingKnapsack(privateKey.getW(), sum);
            result.append(ConversionUtil.bitArrToText(bits));
        }

        return result.toString().trim();
    }

    /**
     * Generate a pair of keys: private and public.
     *
     * @param pass          the string used to generate the keys
     * @param keyHolderName the owner of the key
     */
    @Override
    public void generateKeys(String pass, String keyHolderName) {
        pass = ConversionUtil.textToBinStr(pass);
        pass = StringUtil.rightTruncRightPadWithZeros(pass, KEY_SIZE_BITS);

        Random rnd = Function.getRandomGenerator64(pass);
        Knapsack superKnapsack = new Knapsack(KNAPSACK_SIZE, rnd);

        BigInteger m = Function.generateRandomPositiveInteger(rnd);
        BigInteger p = Function.generateRandomPrimeBigIntegerBiggerThan(superKnapsack.sum(), rnd);
        Knapsack regularKnapsack = superKnapsack.toRegularKnapsack(m, p);

        this.publicKey = new KnapsackPublicKey(keyHolderName, regularKnapsack);
        this.privateKey = new KnapsackPrivateKey(m, p, superKnapsack);
    }

    /**
     * Solve the input super increasing knapsack.
     * @param w the super increasing knapsack to be solved
     * @param sum the desired sum
     * @return the resulting sequence of binary digits
     */
    @Override
    public Bit[] solveSuperIncreasingKnapsack(Knapsack w, BigInteger sum) {
        Bit[] result = new Bit[w.getSize()];
        for (int i = w.getSize() - 1; i >= 0; i--) {
            BigInteger current = w.memberAt(i);
            boolean include = current.compareTo(sum) <= 0;
            result[i] = Bit.constructFromBoolean(include);
            if (include) sum = sum.subtract(current);
        }
        return result;
    }

    /**
     * Private helper method to encrypt one block.
     *
     * @param block one block of the plaintext (4 bytes)
     * @param wp    a regular knapsack
     * @return sum of selected elements (based on the block of plaintext) in the knapsack
     */
    private BigInteger encryptOneBlock(Word block, Knapsack wp) {
        Bit[] bits = block.toBitArr();
        return wp.sumSelective(bits);
    }
}