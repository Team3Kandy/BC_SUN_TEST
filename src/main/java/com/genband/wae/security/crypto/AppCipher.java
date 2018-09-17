/*
 * File Name:   AppCipher.java
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

import com.genband.logging.userbasedlogger.Logger;
import com.genband.wae.security.exception.CryptoException;
import com.genband.wae.security.exception.KeyMgmtException;
import com.genband.wae.security.utils.CryptoUtils;
import org.apache.log4j.Level;

import java.io.UnsupportedEncodingException;

/**
 * This class is a common crypto utility for application data security
 *
 * @author MULI 2011 March - G.Larson This class may not function in WAE. It was used in VSP. 2012 March - H.Semerci
 *         This class modified to function in WAE with JDK. It was used in VSP with IBMJDK.
 */
public class AppCipher extends AbstractCipher {

    protected static Logger logger = Logger.getLogger(AppCipher.class.getName());
    // singleton instance
    private static AppCipher APPCIPHER_INSTANCE = null;

    protected void setCipherAlias() {
        iCipherAlias = CipherConfig.APP_CIPHER;
    }

    // ====================== Singleton methods ======================
    protected AppCipher() {
        super();
    }

    /**
     * Get singleton instance
     *
     * @return
     * @throws CryptoException
     * @throws KeyMgmtException
     */
    public static AppCipher getInstance() throws CryptoException, KeyMgmtException {

        if (APPCIPHER_INSTANCE == null) {
            APPCIPHER_INSTANCE = new AppCipher();
        }
        return APPCIPHER_INSTANCE;
    }

    // ================ Encrypt the input param and return the cipher text as
    // hex string ================
    public synchronized String encrypt(String pPlainText) throws CryptoException {
        try {
            return encrypt(pPlainText.getBytes(CryptoUtils.CHAR_SET));
        } catch (UnsupportedEncodingException e) {
            throw new CryptoException(e.getMessage(), e);
        }
    }

    public String encryptByKey(String pPlainText, String sharedKey) throws CryptoException {
        String encryptedText;
        try {
            int keyLength = sharedKey.length();
            if (logger.isEnabledFor(Level.DEBUG)) {
                logger.debug("encryptByKey text:" + pPlainText + ", key length: " + keyLength);
            }

            switch (keyLength) {
            case 16:
                encryptedText = encryptBy128BitsKey(pPlainText, sharedKey);
                break;
            case 24:
                encryptedText = encryptBy192BitsKey(pPlainText, sharedKey);
                break;
            case 32:
                encryptedText = encryptBy256BitsKey(pPlainText, sharedKey);
                break;

            default:
                encryptedText = encryptBy128BitsKey(pPlainText, sharedKey);
                break;
            }
            return encryptedText;
        } catch (CryptoException e) {
            throw new CryptoException(e.getMessage(), e);
        }
    }

    public String encryptBy128BitsKey(String pPlainText, String sharedKey) throws CryptoException {
        try {
            String encryptingText;
            if (logger.isEnabledFor(Level.DEBUG)) {
                logger.debug("Start 128 bits encryption on :" + pPlainText + ", by key: " + sharedKey);
            }
            encryptingText = encryptBy128BitsKey(pPlainText.getBytes(CryptoUtils.CHAR_SET), sharedKey);
            if (logger.isEnabledFor(Level.DEBUG)) {
                logger.debug("End 128 bits encryption on :" + pPlainText + " encrypted as : " + encryptingText);
            }

            return encryptingText;
        } catch (UnsupportedEncodingException e) {
            throw new CryptoException(e.getMessage(), e);
        }
    }

    public String encryptBy192BitsKey(String pPlainText, String sharedKey) throws CryptoException {
        try {
            String encryptingText;
            if (logger.isEnabledFor(Level.DEBUG)) {
                logger.debug("Start 192 bits encryption on :" + pPlainText + ", by key: " + sharedKey);
            }
            encryptingText = encryptBy192BitsKey(pPlainText.getBytes(CryptoUtils.CHAR_SET), sharedKey);
            if (logger.isEnabledFor(Level.DEBUG)) {
                logger.debug("End 192 bits encryption on :" + pPlainText + " encrypted as : " + encryptingText);
            }

            return encryptingText;
        } catch (UnsupportedEncodingException e) {
            throw new CryptoException(e.getMessage(), e);
        }
    }

    public String encryptBy256BitsKey(String pPlainText, String sharedKey) throws CryptoException {
        try {
            String encryptingText;
            if (logger.isEnabledFor(Level.DEBUG)) {
                logger.debug("Start 256 bits encryption on :" + pPlainText + ", by key: " + sharedKey);
            }
            encryptingText = encryptBy256BitsKey(pPlainText.getBytes(CryptoUtils.CHAR_SET), sharedKey);
            if (logger.isEnabledFor(Level.DEBUG)) {
                logger.debug("End 256 bits encryption on :" + pPlainText + " encrypted as : " + encryptingText);
            }

            return encryptingText;
        } catch (UnsupportedEncodingException e) {
            throw new CryptoException(e.getMessage(), e);
        }
    }

    public String encrypt(int pInt) throws CryptoException {
        return encrypt(CryptoUtils.intToBytes(pInt));
    }

    public String encrypt(long pLong) throws CryptoException {
        return encrypt(CryptoUtils.longToBytes(pLong));
    }

    public String encrypt(float pFloat) throws CryptoException {
        return encrypt(CryptoUtils.floatToBytes(pFloat));
    }

    public String encrypt(double pDouble) throws CryptoException {
        return encrypt(CryptoUtils.doubleToBytes(pDouble));
    }

    // =============== Decrypt a hex string to a given type ===============
    public synchronized String decrypt(String pCipherText) throws CryptoException {
        try {
            return new String(decryption(pCipherText), CryptoUtils.CHAR_SET);
        } catch (UnsupportedEncodingException e) {
            throw new CryptoException(e.getMessage(), e);
        }
    }

    public String decryptByKey(String pCipherText, String sharedKey) throws CryptoException {
        String decryptedText;
        try {
            int keyLength = sharedKey.length();
            if (logger.isEnabledFor(Level.DEBUG)) {
                logger.debug("decryptByKey text:" + pCipherText + ", key length: " + keyLength);
            }

            switch (keyLength) {
            case 16:
                decryptedText = decryptBy128BitsKey(pCipherText, sharedKey);
                break;
            case 24:
                decryptedText = decryptBy192BitsKey(pCipherText, sharedKey);
                break;
            case 32:
                decryptedText = decryptBy256BitsKey(pCipherText, sharedKey);
                break;

            default:
                decryptedText = decryptBy128BitsKey(pCipherText, sharedKey);
                break;
            }
            return decryptedText;
        } catch (CryptoException e) {
            throw new CryptoException(e.getMessage(), e);
        }
    }

    public String decryptBy128BitsKey(String pCipherText, String sharedKey) throws CryptoException {
        try {
            String decryptingText;
            if (logger.isEnabledFor(Level.DEBUG)) {
                logger.debug("Start 128 bits decryption on :" + pCipherText + ", by key: " + sharedKey);
            }
            decryptingText = new String(decryptionBy128BitsKey(pCipherText, sharedKey), CryptoUtils.CHAR_SET);
            if (logger.isEnabledFor(Level.DEBUG)) {
                logger.debug("End 128 bits decryption on :" + pCipherText + " decrypted as : " + decryptingText);
            }

            return decryptingText;
        } catch (UnsupportedEncodingException e) {
            throw new CryptoException(e.getMessage(), e);
        }
    }

    public String decryptBy192BitsKey(String pCipherText, String sharedKey) throws CryptoException {
        try {
            String decryptingText;
            if (logger.isEnabledFor(Level.DEBUG)) {
                logger.debug("Start 192 bits decryption on :" + pCipherText + ", by key: " + sharedKey);
            }
            decryptingText = new String(decryptionBy192BitsKey(pCipherText, sharedKey), CryptoUtils.CHAR_SET);
            if (logger.isEnabledFor(Level.DEBUG)) {
                logger.debug("End 192 bits decryption on :" + pCipherText + " decrypted as : " + decryptingText);
            }

            return decryptingText;
        } catch (UnsupportedEncodingException e) {
            throw new CryptoException(e.getMessage(), e);
        }
    }

    public String decryptBy256BitsKey(String pCipherText, String sharedKey) throws CryptoException {
        try {
            String decryptingText;
            if (logger.isEnabledFor(Level.DEBUG)) {
                logger.debug("Start 256 bits decryption on :" + pCipherText + ", by key: " + sharedKey);
            }
            decryptingText = new String(decryptionBy256BitsKey(pCipherText, sharedKey), CryptoUtils.CHAR_SET);
            if (logger.isEnabledFor(Level.DEBUG)) {
                logger.debug("End 256 bits decryption on :" + pCipherText + " decrypted as : " + decryptingText);
            }

            return decryptingText;
        } catch (UnsupportedEncodingException e) {
            throw new CryptoException(e.getMessage(), e);
        }
    }

    public int decryptAsInt(String pCipherText) throws CryptoException {
        return CryptoUtils.bytesToInt(decryption(pCipherText));
    }

    public long decryptAsLong(String pCipherText) throws CryptoException {
        return CryptoUtils.bytesToLong(decryption(pCipherText));
    }

    public float decryptAsFloat(String pCipherText) throws CryptoException {
        return CryptoUtils.bytesToFloat(decryption(pCipherText));
    }

    public double decryptAsDouble(String pCipherText) throws CryptoException {
        return CryptoUtils.bytesToDouble(decryption(pCipherText));
    }

    // ================ hash methods ================
    public String hash(String pPlainText) throws CryptoException {
        try {
            return hash(pPlainText.getBytes(CryptoUtils.CHAR_SET));
        } catch (UnsupportedEncodingException e) {
            throw new CryptoException(e.getMessage(), e);
        }
    }

    public String hash(int pPlainText) throws CryptoException {
        return hash(CryptoUtils.intToBytes(pPlainText));
    }

    public String hash(long pPlainText) throws CryptoException {
        return hash(CryptoUtils.longToBytes(pPlainText));
    }

    public String hash(float pPlainText) throws CryptoException {
        return hash(CryptoUtils.floatToBytes(pPlainText));
    }

    public String hash(double pPlainText) throws CryptoException {
        return hash(CryptoUtils.doubleToBytes(pPlainText));
    }

    // ================ hash validation methods ================
    public boolean validateHash(String pPlainText, String pHashText) throws CryptoException {
        return validateHash(pPlainText.getBytes(), pHashText);
    }

    public boolean validateHash(int pPlainText, String pHashText) throws CryptoException {
        return validateHash(CryptoUtils.intToBytes(pPlainText), pHashText);
    }

    public boolean validateHash(long pPlainText, String pHashText) throws CryptoException {
        return validateHash(CryptoUtils.longToBytes(pPlainText), pHashText);
    }

    public boolean validateHash(float pPlainText, String pHashText) throws CryptoException {
        return validateHash(CryptoUtils.floatToBytes(pPlainText), pHashText);
    }

    public boolean validateHash(double pPlainText, String pHashText) throws CryptoException {
        return validateHash(CryptoUtils.doubleToBytes(pPlainText), pHashText);
    }

}
