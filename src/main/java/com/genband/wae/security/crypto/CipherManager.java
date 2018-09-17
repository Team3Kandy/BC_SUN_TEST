/*
 * File Name:   CipherManager.java
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
import com.genband.wae.security.keymgmt.KeyManager;
import com.genband.wae.security.utils.CryptoUtils;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Hashtable;

/**
 * This class is to load keys for specific cipher, then initialize and create ciphers according to the configuration
 * 
 * @author MULI
 */
public class CipherManager {

    private static CipherManager MANAGER_INSTANCE = null;

    private KeyManager iKeyManager = null;

    private Hashtable<String, Cipher> iCiphers = null;
    private Hashtable<String, Mac> iMacs = null;

    // ====================== Singleton methods ======================
    private CipherManager() {

        // init key manager
        iKeyManager = new KeyManager();

        // init cipher and mac list
        iCiphers = new Hashtable<String, Cipher>();
        iMacs = new Hashtable<String, Mac>();

    }

    /**
     * Get Singleton instance
     *
     * @return
     * @throws IOException
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws IOException
     */
    public static CipherManager getInstance() throws CryptoException, KeyMgmtException {
        if (MANAGER_INSTANCE == null) {
            MANAGER_INSTANCE = new CipherManager();
        }
        return MANAGER_INSTANCE;
    }

    // ====================== Public APIs ======================
    /**
     * Get a cipher based on its algorithm, key alias and mode. If the cipher list already contains it, get the instance
     * from cipher list, otherwise, create a new instance and store it in the cipher list
     *
     * @param cryptoAlgorithm
     * @param pCipherMode
     * @return
     * @throws CryptoException
     */
    public Cipher getCipher(CryptoAlgorithm cryptoAlgorithm, int pCipherMode) throws CryptoException {

        try {
            Cipher lCipher = null;

            // generate cipher id as hashtable key in the form of
            // CipherAlgorithm|KeyAlias|EncryptionMode
            String lCipherId = cryptoAlgorithm + "|" + pCipherMode;

            // check if the encryptor is already cached in the encryptor list
            if (iCiphers.containsKey(lCipherId)) {
                lCipher = (Cipher) iCiphers.get(lCipherId);
            } else {
                lCipher = CryptoUtils.getInstanceCipherWrapper(cryptoAlgorithm.name());
                Key lSecretKey = iKeyManager.getKey(cryptoAlgorithm.getKeyAlias());
                lCipher.init(pCipherMode, lSecretKey);

                // add to the encryptor list
                iCiphers.put(lCipherId, lCipher);
            }

            return lCipher;

        } catch (Exception e) {
            throw new CryptoException("Failed to initialize the cipher.", e);
        }

    }

    /**
     * Get a mac based on its algorithm, key alias. If the mac list already contains it, get the instance from mac list,
     * otherwise, create a new instance and store it in the mac list
     *
     * @param cipherAlgorithm
     * @return
     * @throws CryptoException
     */
    public Mac getMac(CryptoAlgorithm cipherAlgorithm) throws CryptoException {

        try {

            Mac lMac = null;

            // generate mac id as hashtable key in the form of
            // MacAlgorithm|KeyAlias
            String lMacId = cipherAlgorithm.name() + "|" + cipherAlgorithm.getKeyAlias();

            // check if the mac is already cached in the mac list
            if (iMacs.containsKey(lMacId)) {
                lMac = (Mac) iMacs.get(lMacId);
            } else {
                lMac = CryptoUtils.getInstanceMacWrapper(cipherAlgorithm.name());
                Key lSecretKey = iKeyManager.getKey(cipherAlgorithm.getKeyAlias());
                lMac.init(lSecretKey);

                // add to the encryptor list
                iMacs.put(lMacId, lMac);
            }

            return lMac;
        } catch (Exception e) {
            throw new CryptoException("Failed to initialize the MAC.", e);
        }

    }
}
