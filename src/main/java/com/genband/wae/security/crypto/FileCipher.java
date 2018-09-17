/**
 * File Name:   FileCipher.java
 * Package:     com.nortel.vsp.security.crypto
 *
 * Copyright (c) 2011 GENBAND. All rights reserved. 
 * Use of this software and its contents is subject to the 
 * terms and conditions of the applicable end user or 
 * software license agreement, right to use notice, and 
 * all relevant copyright protections.
 *
 */
package com.genband.wae.security.crypto;

import com.genband.wae.security.exception.CryptoException;
import com.genband.wae.security.exception.KeyMgmtException;
import com.genband.wae.security.utils.CryptoUtils;

import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Properties;

/**
 * This class is a common crypto utility for file data security
 * 
 * @author MULI 2012 March - H.Semerci This class modified to function in WAE with JDK. It was used in VSP with IBMJDK.
 */

public class FileCipher extends AbstractCipher {

    // singleton instance
    private static FileCipher FILECIPHER_INSTANCE = null;

    protected void setCipherAlias() {
        iCipherAlias = CipherConfig.FILE_CIPHER;
    }

    // ====================== Singleton methods ======================
    private FileCipher() {
        super();
    }

    /**
     * Get singleton instance
     * 
     * @return singleton instance
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws UnrecoverableKeyException
     * @throws IOException
     */
    public static FileCipher getInstance() throws CryptoException, KeyMgmtException {
        if (FILECIPHER_INSTANCE == null) {
            FILECIPHER_INSTANCE = new FileCipher();
        }
        return FILECIPHER_INSTANCE;
    }

    /**
     * Encrypt a file and save the encrypted file with specific name
     * 
     * @param pOrigFileName
     * @param pEncFileName
     */
    public void encryptFile(String pOrigFileName, String pEncFileName) throws CryptoException {

        try {
            byte[] lPlainText = CryptoUtils.readRawBytes(pOrigFileName);
            String lCipherText = encrypt(lPlainText);
            CryptoUtils.writeRawBytes(lCipherText.getBytes(), pEncFileName);

        } catch (Exception e) {
            throw new CryptoException("Failed to encrypt file " + pOrigFileName, e);
        }

    }

    /**
     * Decrypt a file and save the decrypted file with specific name
     * 
     * @param pOrigFileName
     * @param pDecFileName
     * @throws UnrecoverableKeyException
     * @throws KeyStoreException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public void decryptFile(String pOrigFileName, String pDecFileName) {

        try {
            byte[] lPlainText = decryptFileAsBytes(pOrigFileName);
            CryptoUtils.writeRawBytes(lPlainText, pDecFileName);

        } catch (Exception e) {
            throw new CryptoException("Failed to decrypt file " + pOrigFileName, e);
        }

    }

    public byte[] decryptFileAsBytes(String pOrigFileName) throws CryptoException {
        try {
            byte[] lCipherText = CryptoUtils.readRawBytes(pOrigFileName);
            String lCipherTextStr = new String(lCipherText);
            byte[] lPlainText = null;
            if (lCipherTextStr != null && super.getCipherText(lCipherTextStr) == null) {
                // the cipher text is in clear
                lPlainText = lCipherText;

                // encrypt it
                encryptFile(pOrigFileName, pOrigFileName);

            } else {
                lPlainText = decryption(lCipherTextStr);
            }
            return lPlainText;
        } catch (Exception e) {
            throw new CryptoException("Failed to decrypt file " + pOrigFileName, e);
        }

    }

    public String decryptFileAsString(String pOrigFilename) throws CryptoException {
        return new String(this.decryptFileAsBytes(pOrigFilename));
    }

    public Properties decryptFileAsProperties(String pOrigFilename) throws CryptoException {
        try {
            ByteArrayInputStream lPropertyIS = new ByteArrayInputStream(this.decryptFileAsBytes(pOrigFilename));

            Properties lProperties = new Properties();
            lProperties.load(lPropertyIS);
            return lProperties;
        } catch (Exception e) {
            throw new CryptoException("Failed to load encoded properties from file " + pOrigFilename, e);
        }
    }

    /**
     * Command line tool. Syntax is [enc|dec] orig_file dest_file Example: <JAVA_HOME>/bin/java -cp <JAR file full path>
     * com.nortel.vsp.security.FileCipher [enc|dec] orig_file dest_file
     * 
     * @param pArg
     */
    public static void main(String pArg[]) {
        FileCipher lFileCipher = FileCipher.getInstance();
        String CMD_ENC = "enc";
        String CMD_DEC = "dec";
        String HELP_MSG = "Syntax is: [enc|dec] orig_filename dest_filename";

        // validate command syntax
        if (pArg.length < 1 || pArg.length > 3
                || (!pArg[0].equalsIgnoreCase(CMD_ENC) && !pArg[0].equalsIgnoreCase(CMD_DEC))) {
            System.out.println(HELP_MSG);
            return;
        }

        // encrypt or decrypt
        if (pArg[0].equalsIgnoreCase(CMD_ENC)) {
            lFileCipher.encryptFile(pArg[1], pArg[2]);
        } else if (pArg[0].equalsIgnoreCase(CMD_DEC)) {
            lFileCipher.decryptFile(pArg[1], pArg[2]);
        }

        return;

    }

}
