/*
 * File Name:   AbstractCipher.java
 * Package:     com.genband.wae.security.crypto
 *
 * CONFIDENTIALITY AND LIMITED USE: This software, including any software of
 * third parties embodied herein, contains code, information, data and concepts
 * which are confidential and/or proprietary to Nortel Networks and such third
 * parties. This software is licensed for use solely in accordance with the
 * terms and conditions of the applicable license agreement with
 * Nortel Networks or its authorized distributor, and not for any other use or
 * purpose. No redistribution of this software by any party is permitted.
 *
 * Copyright \250 2007-2008 Nortel Networks. All Rights Reserved.
 *
 */
package com.genband.wae.security.crypto;

import com.genband.wae.security.crypto.CipherConfig.CryptoAlgorithm;
import com.genband.wae.security.exception.CryptoException;
import com.genband.wae.security.exception.KeyMgmtException;
import com.genband.wae.security.utils.CryptoUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.StringTokenizer;
import java.util.regex.Pattern;

/**
 * Abstract Cipher defines skeleton of a cipher and provides fundamental methods
 * 
 * @author MULI 2011 March - G.Larson This class may not function in WAE. It was used in VSP. 2012 March - H.Semerci
 *         This class modified to function in WAE with JDK. It was used in VSP with IBMJDK.
 */

public abstract class AbstractCipher {

    private static String SEPERATOR = "|";

    private static String ENCRYPTION_PATTERN = "^\\S+\\|\\S+";

    private static String HASH_PATTERN = "^\\S+\\|\\S+";

    /** An alias that uniquely identify the cipher instance */
    protected CipherConfig iCipherAlias = null;

    /** Cipher Manager */
    protected CipherManager iCipherManager;

    /** encryption cipher instance */
    private Cipher iEncryptor = null;

    /** encryption prefix: this is intended to solved backward compatibility */
    private String iEncryptionPrefix = null;

    /** mac instance for hash */
    private Mac iMac = null;

    /** hash prefix: this is intended to solved backward compatibility */
    private String iHashPrefix = null;

    // ====================== Private mehods ======================
    /**
     * Set the cipher alias
     */
    abstract protected void setCipherAlias();

    /**
     * Constructor which retrieve the cipher instance and initialize the secret key
     * 
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IOException
     * @throws CertificateException
     * @throws KeyStoreException
     * @throws UnrecoverableKeyException
     */
    protected AbstractCipher() throws CryptoException, KeyMgmtException {

        // init cipher alias
        setCipherAlias();

        // init CipherManager
        iCipherManager = CipherManager.getInstance();

        // init encryptor
        iEncryptor = getEncryptor();
        iEncryptionPrefix = getEncryptionPrefix();

        // init MAC
        iMac = getMac();
        iHashPrefix = getMacPrefix();

    }

    /**
     * Return the encryption prefix for this cipher: (encryption_algorithm|encryption_key_alias)
     * 
     * @return
     */
    private String getEncryptionPrefix() {
        return iCipherAlias.getEncryptionAlgorithm().ordinal() + SEPERATOR;
    }

    /**
     * Return the cipher text hex string without prefix
     * 
     * @param pEncryptionText
     * @return
     */
    protected String getCipherText(String pEncryptionText) {
        // validate if the cipher text are in the right form:
        // (CiphertAlgorithm|KeyAlias)HexStrCipherText
        if (Pattern.matches(ENCRYPTION_PATTERN, pEncryptionText)) {
            StringTokenizer lStrTok = new StringTokenizer(pEncryptionText, SEPERATOR);
            lStrTok.nextToken();
            return lStrTok.nextToken();
        } else {
            return null;
        }
    }

    /**
     * Return Mac prefix string for this cipher: (mac_algorithm|mac_key_alias)
     * 
     * @return
     */
    private String getMacPrefix() {
        return iCipherAlias.getMACAlgorithm().ordinal() + SEPERATOR;
    }

    /**
     * Get Hash string with our prefix
     * 
     * @param pHashText
     * @return
     */
    protected String getDigestText(String pHashText) {

        // validate if the mac digest text are in the right form:
        // (MacAlgorithm|KeyAlias)HexStrDigestText
        if (Pattern.matches(HASH_PATTERN, pHashText)) {
            StringTokenizer lStrTok = new StringTokenizer(pHashText, SEPERATOR);
            lStrTok.nextToken();
            return lStrTok.nextToken();
        } else {
            return null;
        }
    }

    /**
     * Create a descryptor based on the input cipher string's prefix
     * 
     * @param pCipherText
     * @return
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws KeyStoreException
     * @throws UnrecoverableKeyException
     */
    private Cipher getDecryptor(String pCipherText) throws CryptoException {

        Cipher lDecryptor = null;

        // validate if the cipher text are in the right form:
        // (CiphertAlgorithm|KeyAlias)HexStrCipherText
        if (Pattern.matches(ENCRYPTION_PATTERN, pCipherText)) {
            StringTokenizer lStrTok = new StringTokenizer(pCipherText, SEPERATOR);
            int code = Integer.parseInt(lStrTok.nextToken());
            //System.out.println("CODE------> " + code);
            CryptoAlgorithm cipherAlgorithm = CipherConfig.CryptoAlgorithm.getCryptoAlgorithm(code);
            /*System.out.println("CIPHER ALG NAME------> " + cipherAlgorithm.name());
            System.out.println("CIPHER ALG CODE------> " + cipherAlgorithm.getCode());
            System.out.println("CIPHER ALG NEVARSA------> " + cipherAlgorithm.getKeyAlias());*/
            lDecryptor = iCipherManager.getCipher(cipherAlgorithm, Cipher.DECRYPT_MODE);
            //System.out.println("CIPHER ALG NEVARSA----***--> " + lDecryptor.getAlgorithm());
        }

        return lDecryptor;

    }

    /**
     * @param pHashText
     * @return
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws UnrecoverableKeyException
     */
    private Mac getMac(String pHashText) throws CryptoException {

        Mac lMac = null;

        // validate if the mac digest text are in the right form:
        // (MacAlgorithm|KeyAlias)HexStrDigestText
        if (Pattern.matches(HASH_PATTERN, pHashText)) {
            StringTokenizer lStrTok = new StringTokenizer(pHashText, SEPERATOR);
            int code = Integer.parseInt(lStrTok.nextToken());
            CryptoAlgorithm cipherAlgorithm = CipherConfig.CryptoAlgorithm.getCryptoAlgorithm(code);

            lMac = iCipherManager.getMac(cipherAlgorithm);
        }

        return lMac;

    }

    /**
     * This method is to get encryption secret key from key management system
     * 
     * @return
     * @throws UnrecoverableKeyException
     * @throws KeyStoreException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    private Cipher getEncryptor() throws CryptoException {
        return iCipherManager.getCipher(iCipherAlias.getEncryptionAlgorithm(), Cipher.ENCRYPT_MODE);
    }

    /**
     * This method is to get mac secret key from key management system.
     * 
     * @return
     * @throws UnrecoverableKeyException
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    private Mac getMac() throws CryptoException {
        return iCipherManager.getMac(iCipherAlias.getMACAlgorithm());
    }

    // ====================== Public APIs ======================
    /**
     * Encrypt the input clear text and return the encryption result as:
     * (encrytion_algorithm|encryption_key_alias)cipher_text_hex_string
     */
    public String encrypt(byte[] pPlainText) throws CryptoException {
        try {
            return iEncryptionPrefix + CryptoUtils.bytesToHexStr(iEncryptor.doFinal(pPlainText));
        } catch (Exception e) {
            throw new CryptoException("Failed to encrypt the input " + new String(pPlainText), e);
        }
    }

    /**
     * This method is to get encryption by means of shared secret key it is used for now with anonymous call
     */
    public String encryptBy128BitsKey(byte[] pPlainText, String sharedKey) throws CryptoException {
        try {
            Cipher lCipher = null;
            lCipher = CryptoUtils.getInstanceCipherWrapper(iCipherAlias.getEncryptionAlgorithm().name());
            Key lSecretKey = new SecretKeySpec(sharedKey.getBytes(), "AES");
            lCipher.init(Cipher.ENCRYPT_MODE, lSecretKey);
            return CryptoUtils.bytesToHexStr(lCipher.doFinal(pPlainText));
        } catch (Exception e) {
            throw new CryptoException("Failed to encrypt the input " + new String(pPlainText), e);
        }
    }

    public String encryptBy192BitsKey(byte[] pPlainText, String sharedKey) throws CryptoException {
        try {
            Cipher lCipher = null;
            lCipher = CryptoUtils.getInstanceCipherWrapper(CipherConfig.APP_CIPHER_AES_192.getEncryptionAlgorithm().name());
            Key lSecretKey = new SecretKeySpec(sharedKey.getBytes(), "AES");
            lCipher.init(Cipher.ENCRYPT_MODE, lSecretKey);
            return CryptoUtils.bytesToHexStr(lCipher.doFinal(pPlainText));
        } catch (Exception e) {
            throw new CryptoException("Failed to encrypt the input " + new String(pPlainText), e);
        }
    }

    public String encryptBy256BitsKey(byte[] pPlainText, String sharedKey) throws CryptoException {
        try {
            Cipher lCipher = null;
            lCipher = CryptoUtils.getInstanceCipherWrapper(CipherConfig.APP_CIPHER_AES_256.getEncryptionAlgorithm().name());
            Key lSecretKey = new SecretKeySpec(sharedKey.getBytes(), "AES");
            lCipher.init(Cipher.ENCRYPT_MODE, lSecretKey);
            return CryptoUtils.bytesToHexStr(lCipher.doFinal(pPlainText));
        } catch (Exception e) {
            throw new CryptoException("Failed to encrypt the input " + new String(pPlainText), e);
        }
    }

    /**
     * This method is to do decryption by means of shared secret key it is used for now with anonymous call
     */
    public byte[] decryptionBy128BitsKey(String pSecretText, String sharedKey) throws CryptoException {

        try {
            Cipher lCipher = null;
            lCipher = CryptoUtils.getInstanceCipherWrapper(iCipherAlias.getEncryptionAlgorithm().name());
            Key lSecretKey = new SecretKeySpec(sharedKey.getBytes(), "AES");
            lCipher.init(Cipher.DECRYPT_MODE, lSecretKey);
            byte[] lCipherBytes = CryptoUtils.hexStrToBytes(pSecretText);
            return lCipher.doFinal(lCipherBytes);
        } catch (Exception e) {
            throw new CryptoException("Failed to decrypt the input " + pSecretText, e);
        }
    }

    public byte[] decryptionBy192BitsKey(String pSecretText, String sharedKey) throws CryptoException {

        try {
            Cipher lCipher = null;
            lCipher = CryptoUtils.getInstanceCipherWrapper(CipherConfig.APP_CIPHER_AES_192.getEncryptionAlgorithm().name());
            Key lSecretKey = new SecretKeySpec(sharedKey.getBytes(), "AES");
            lCipher.init(Cipher.DECRYPT_MODE, lSecretKey);
            byte[] lCipherBytes = CryptoUtils.hexStrToBytes(pSecretText);
            return lCipher.doFinal(lCipherBytes);
        } catch (Exception e) {
            throw new CryptoException("Failed to decrypt the input " + pSecretText, e);
        }
    }

    public byte[] decryptionBy256BitsKey(String pSecretText, String sharedKey) throws CryptoException {

        try {
            Cipher lCipher = null;
            lCipher = CryptoUtils.getInstanceCipherWrapper(CipherConfig.APP_CIPHER_AES_256.getEncryptionAlgorithm().name());
            Key lSecretKey = new SecretKeySpec(sharedKey.getBytes(), "AES");
            lCipher.init(Cipher.DECRYPT_MODE, lSecretKey);
            byte[] lCipherBytes = CryptoUtils.hexStrToBytes(pSecretText);
            return lCipher.doFinal(lCipherBytes);
        } catch (Exception e) {
            throw new CryptoException("Failed to decrypt the input " + pSecretText, e);
        }
    }

    /**
     * Decrypt the text in the format of (encryption_algorithm|encryption_key_alias)cipher_text_hex_string
     * 
     * @param pSecretText
     * @return
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws KeyStoreException
     * @throws UnrecoverableKeyException
     */
    public byte[] decryption(String pSecretText) throws CryptoException {

        try {
            Cipher lDecryptor = getDecryptor(pSecretText);
            byte[] lCipherBytes = CryptoUtils.hexStrToBytes(getCipherText(pSecretText));
            return lDecryptor.doFinal(lCipherBytes);
        } catch (Exception e) {
            throw new CryptoException("Failed to decrypt the input " + pSecretText, e);
        }

    }

    /**
     * Generate digest
     * 
     * @param pPlainText
     * @return
     */
    public String hash(byte[] pPlainText) throws CryptoException {
        try {
            return iHashPrefix + CryptoUtils.bytesToHexStr(iMac.doFinal(pPlainText));
        } catch (Exception e) {
            throw new CryptoException("Failed to hash " + new String(pPlainText), e);
        }
    }

    /**
     * Validate if hash(input raw bytes pPlainText) = the given hash text pHashText
     * 
     * @param pPlainText
     * @param pHashText
     * @return
     * @throws CryptoException
     */
    public boolean validateHash(byte[] pPlainText, String pHashText) throws CryptoException {

        try {
            Mac lMac = this.getMac(pHashText);

            return CryptoUtils.bytesToHexStr(lMac.doFinal(pPlainText)).equalsIgnoreCase(getDigestText(pHashText));
        } catch (Exception e) {
            throw new CryptoException("Failed to validate the hash " + new String(pPlainText), e);
        }

    }
}
