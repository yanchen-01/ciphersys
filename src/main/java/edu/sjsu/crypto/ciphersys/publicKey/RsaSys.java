package edu.sjsu.crypto.ciphersys.publicKey;

import edu.sjsu.yazdankhah.crypto.util.abstracts.RsaAbs;
import edu.sjsu.yazdankhah.crypto.util.ciphersysdatatypes.*;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.*;

import java.math.BigInteger;
import java.util.Random;

import lombok.Getter;

/**
 * RSA cipher system.
 * @author Yan Chen
 * Customer: Sida Zhong
 */
@Getter
public class RsaSys extends RsaAbs {
    private RsaPublicKey publicKey;
    private RsaPrivateKey privateKey;

    /**
     * Instantiates a new RSA cipher system.
     */
    public RsaSys() {
        publicKey = new RsaPublicKey(null, null, null);
        privateKey = new RsaPrivateKey(null, null);
    }

    /**
     * Encrypt the plaintext to cipher in hex using the public key.
     *
     * @param plaintext the plaintext
     * @param publicKey the RSA public key
     * @return cipher in hex string
     */
    @Override
    public String encrypt(String plaintext, RsaPublicKey publicKey) {
        BigInteger[] textBlocks = ConversionUtil.textToBigIntegerArr(plaintext, PLAIN_BLOCK_SIZE_BITS);

        for (int i = 0; i < textBlocks.length; i++)
            textBlocks[i] = encryptOneBlock(textBlocks[i], publicKey);

        return ConversionUtil.bigIntegerArrToHexStr(textBlocks, CIPHER_BLOCK_SIZE_BITS);
    }

    /**
     * Decrypt the cipher in hex to plaintext using the private key.
     *
     * @param ciphertext the cipher hex string
     * @param privateKey the RSA private key
     * @return plaintext
     */
    @Override
    public String decrypt(String ciphertext, RsaPrivateKey privateKey) {
        BigInteger[] textBlocks = ConversionUtil.hexStrToBigIntegerArr(ciphertext, CIPHER_BLOCK_SIZE_BITS);

        for (int i = 0; i < textBlocks.length; i++)
            textBlocks[i] = decryptOneBlock(textBlocks[i], privateKey);

        return ConversionUtil.bigIntegerArrToText(textBlocks, PLAIN_BLOCK_SIZE_BITS).trim();
    }

    /**
     * Generate a pair of keys: private and public.
     *
     * @param pass          the string used to generate the keys
     * @param keyHolderName the owner of the keys
     */
    @Override
    public void generateKeys(String pass, String keyHolderName) {
        pass = ConversionUtil.textToBinStr(pass);
        pass = StringUtil.rightTruncRightPadWithZeros(pass, KEY_SIZE_BITS);

        Random rnd = Function.getRandomGenerator64(pass);

        BigInteger p = Function.generateRandomPrimeBigInteger(P_SIZE_BITS, rnd);
        BigInteger q = Function.generateRandomPrimeBigInteger(Q_SIZE_BITS, rnd);
        BigInteger e = Function.generateRandomPrimeBigInteger(E_SIZE_BITS, rnd);

        BigInteger N = p.multiply(q);
        BigInteger lambda = minusOne(p).multiply(minusOne(q));
        BigInteger d = e.modInverse(lambda);

        publicKey = new RsaPublicKey(keyHolderName, N, e);
        privateKey = new RsaPrivateKey(N, d);
    }

    /**
     * Private helper method to encrypt one block.
     *
     * @param block     one block (64-bit) of the plaintext
     * @param publicKey the public key
     * @return encrypted block (64-bit)
     */
    private BigInteger encryptOneBlock(BigInteger block, RsaPublicKey publicKey) {
        BigInteger e = publicKey.getE();
        BigInteger N = publicKey.getN();
        return block.modPow(e, N);
    }

    /**
     * Private helper method to decrypt one block.
     *
     * @param block      one block (128-bit) of the ciphertext
     * @param privateKey the private key
     * @return encrypted block (128-bit)
     */
    private BigInteger decryptOneBlock(BigInteger block, RsaPrivateKey privateKey) {
        BigInteger d = privateKey.getD();
        BigInteger N = privateKey.getN();
        return block.modPow(d, N);
    }

    /**
     * Private helper method to -1 from a BigInteger.
     *
     * @param i a BigInteger to be subtracted
     * @return input i - 1
     */
    private BigInteger minusOne(BigInteger i) {
        return i.subtract(BigInteger.ONE);
    }

}