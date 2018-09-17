/**
 * File Name:   CryptoUtils.java
 * Package:     com.genband.wae.security.utils
 * 
 * Copyright (c) 2011 GENBAND. All rights reserved. 
 * Use of this software and its contents is subject to the 
 * terms and conditions of the applicable end user or 
 * software license agreement, right to use notice, and 
 * all relevant copyright protections.
 */
package com.genband.wae.security.utils;

import com.genband.logging.userbasedlogger.Logger;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * This is a class provides utility methods for cryptographic functions
 */
public class CryptoUtils {

    public static String CHAR_SET = "UTF-8";
    public static String SHA256 = "SHA-256";
    public static String MAC_SHA1 = "PBKDF2WithHmacSHA1";
    public static String SHA1_RANDOM = "SHA1PRNG";
    private static File jitcFlagFile= new File("/.jitc_system.flag");
    private static Logger log = Logger.getLogger(CryptoUtils.class.getName());
    private static boolean jitcFlag=checkJitcFlagFile();

    public static boolean isJitcFlag() {

        return true;
    }

    // ================= conversion between byte array and common java types
    // =================

    public static byte[] intToBytes(int pInt) {

        ByteBuffer buff = ByteBuffer.allocate(Integer.SIZE);
        buff.putInt(pInt);
        return buff.array();
    }

    public static int bytesToInt(byte[] pBytes) {
        return ByteBuffer.wrap(pBytes).getInt();
    }

    public static byte[] longToBytes(long pLong) {
        ByteBuffer buff = ByteBuffer.allocate(Long.SIZE);
        buff.putLong(pLong);
        return buff.array();
    }

    public static long bytesToLong(byte[] pBytes) {
        return ByteBuffer.wrap(pBytes).getLong();
    }

    public static byte[] floatToBytes(float pFloat) {
        ByteBuffer buff = ByteBuffer.allocate(Float.SIZE);
        buff.putFloat(pFloat);
        return buff.array();
    }

    public static float bytesToFloat(byte[] pBytes) {
        return ByteBuffer.wrap(pBytes).getFloat();
    }

    public static byte[] doubleToBytes(double pDouble) {
        ByteBuffer buff = ByteBuffer.allocate(Double.SIZE);
        buff.putDouble(pDouble);
        return buff.array();
    }

    public static double bytesToDouble(byte[] pBytes) {
        return ByteBuffer.wrap(pBytes).getDouble();
    }

    // ================= conversion between byte array and hex string
    // =================
    // We convert binary values to / from hex String to allow storage in DB
    // as string (varchar). Note that these functions need to preserve
    // leading zeros.
    // If non-hex characters are present, this returns junk.

    private final static char[] hexArray = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E',
            'F' };

    // if needed for performance...
    public static int toHexChars(byte[] bytes, char[] chars, int pos) {
        int v;
        for (int j = 0; j < bytes.length; j++) {
            v = bytes[j] & 0xFF; // & 0xff why? avoid sign extension?
            chars[pos] = hexArray[v / 16];
            pos++;
            chars[pos] = hexArray[v % 16];
            pos++;
        }
        return pos;
    }

    /**
     * Convert a byte array to hex string
     * 
     * @param bytes
     * @return
     */
    public static String bytesToHexStr(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        int v;
        for (int j = 0; j < bytes.length; j++) {
            v = bytes[j] & 0xFF; // & 0xff why? avoid sign extension?
            hexChars[j * 2] = hexArray[v / 16];
            hexChars[j * 2 + 1] = hexArray[v % 16];
        }
        return new String(hexChars);
    }

    /**
     * Convert a hex string to byte array
     *
     * @param s
     * @return
     */
    public static byte[] hexStrToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        len--; // don't trap on odd length String.
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    // ================= read/write bytes from/into a file =================

    /**
     * Read bytes from a file
     * 
     * @param pFileName
     * @return
     * @throws IOException
     * @throws FileNotFoundException
     */
    public static byte[] readRawBytes(String pFileName) throws FileNotFoundException, IOException {

        byte[] lByteBuf = new byte[(int) new File(pFileName).length()];
        new RandomAccessFile(pFileName, "r").readFully(lByteBuf);
        return lByteBuf;

    }

    /**
     * Create a file with the given name and write bytes into it
     * 
     * @param pRawBytes
     * @param pFileName
     * @throws IOException
     */
    public static void writeRawBytes(byte[] pRawBytes, String pFileName) throws IOException {

        FileOutputStream lFos = new FileOutputStream(pFileName);
        lFos.write(pRawBytes);
        lFos.close();

    }

    public static byte[] getSHA256(String input) {
        try {
            byte[] bytesOfMessage = input.getBytes(CHAR_SET);
            byte[] key = null;
            if(isJitcFlag()) {
                MessageDigest md = MessageDigest.getInstance(SHA256, "BCFIPS");
                key = md.digest(bytesOfMessage);
                key = Arrays.copyOf(key, 16);
            }
            else {
                MessageDigest md = MessageDigest.getInstance(SHA256);
                key = md.digest(bytesOfMessage);
                key = Arrays.copyOf(key, 16);
            }
            return key;
        } catch (Exception e) {
            return null;
        }
    }

    // constants for password hashing
    static final int saltSize = 4; // bytes
    static final int hashBits = 160; // 160 bits
    static final int hashBytes = 20; // 40 HEX chars

    // Validate clear password against encoded password.
    // The encoded password is salt:hash
    // This method, because it is run often, is a candidate for optimization.
    /**
     * Validate clear password against encoded password. The encoded password is salt:hash This method, because it is
     * run often, is a candidate for optimization.
     * 
     * @return boolean true if clearPass matches encoded password
     */
    public static boolean pwEquals(String clearPass, String encPass) {

        if (encPass == null)
            return false;
        if (encPass.length() == 0)
            return false;

        String[] saltHash = encPass.split(":");

        if (saltHash.length < 2) {
            // If we wanted to allow clear-text passwords in the DB we could
            // do it here, provided they don't contain ":"
            return clearPass.equals(encPass);
        }

        byte[] salt = hexStrToBytes(saltHash[0]);

        // Different salt sizes could be used, I suppose.
        // if ( salt.length != saltSize) {
        // say("ERROR: salt length: "+salt.length);
        if (salt.length == 0) {
            // Some salt is required.
            say("missing salt");
            return false;
        }

        byte[] hash = hexStrToBytes(saltHash[1]);

        if (hash.length != hashBytes) {
            // Currently no support for different hash sizes in DB.
            // This would require a different KeySpec.
            say("ERROR:: hash length: " + hash.length);
            return false;
        }
        PBEKeySpec ks = newKeySpec(clearPass, salt);

        byte[] hash2;
        try {
            hash2 = keyFactory.generateSecret(ks).getEncoded();
        } catch (InvalidKeySpecException e) {
            // never
            e.printStackTrace();
            return false;
        }

        // compare the hashed clearPass with the one stored in DB.
        if (hash2.length != hash.length)
            return false;
        for (int x = 0; x < hash.length; x++)
            if (hash[x] != hash2[x])
                return false;

        // The hashes are equal
        return true;
    }

    /**
     * Encode a clear-text password into a salt:hash string. The salt is generated within this function. If you are
     * trying to encode with a known salt, you probably want method pwEquals above
     * 
     * @param clearPass
     * @return String salt:hash of clearPass
     */
    public static String encodePassword(String clearPass) {
        if (clearPass == null)
            return null;
        if (clearPass.length() == 0)
            return null;

        PBEKeySpec spec = newKeySpec(clearPass, null);

        byte[] salt = spec.getSalt();

        byte[] hashed;
        try {
            hashed = keyFactory.generateSecret(spec).getEncoded();
        } catch (InvalidKeySpecException e) {
            // never
            e.printStackTrace();
            return null;
        }

        // Performance could be improved, but this method is only used when
        // password is set.
        return bytesToHexStr(salt) + ":" + bytesToHexStr(hashed);
    }

    public static String encodeWithSHA1(String clearText){
        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance("SHA-1");
            messageDigest.update(clearText.getBytes());
            byte[] messageDigestSHA1 = messageDigest.digest();
            StringBuffer stringBuffer = new StringBuffer();
            for (byte bytes : messageDigestSHA1) {
                stringBuffer.append(String.format("%02x", bytes & 0xff));
            }
            return stringBuffer.toString();
        } catch (NoSuchAlgorithmException exception) {
            // TODO Auto-generated catch block
            exception.printStackTrace();
            return null;
        }
    }

    // For now, don't worry about concurrency on these.
    // keyFactory, because it is stateless (mostly).
    private static final SecretKeyFactory keyFactory = _keyFactory();

    // construct when class is loaded.
    private static SecretKeyFactory _keyFactory() {

        // PBKDF2WithHmacSHA1 is:
        // Password Based Key Derivation Function 2 with
        // Hash-based Message Authenication Code
        // (SHA1 message digest)
        // http://download.oracle.com/javase/6/docs/technotes/guides/security/SunProviders.html
        // http://en.wikipedia.org/wiki/PBKDF2
        // http://en.wikipedia.org/wiki/HMAC

        try {
            if(isJitcFlag()) {
                return SecretKeyFactory.getInstance(MAC_SHA1, "BCFIPS");
            }
            else {
                return SecretKeyFactory.getInstance(MAC_SHA1);
            }
        } catch (NoSuchAlgorithmException e) {
            // never
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }

    // sRand probably has it's own mutex and we are not using it
    // that often.
    private static final SecureRandom sRand = _sRand();

    // construct when class is loaded
    private static SecureRandom _sRand() {
        try {
            if(isJitcFlag()) {
                return SecureRandom.getInstance("DEFAULT", "BCFIPS");
            }
            else{
                return SecureRandom.getInstance(SHA1_RANDOM);
            }
        } catch (NoSuchAlgorithmException e) {
            // never
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }

    // create a key specifiction from password and salt.
    // The salt may be null, in which case, a random salt is
    // used. You will need to retrieve the random salt from
    // the returned KeySpec.
    private static PBEKeySpec newKeySpec(String password, byte[] salt) {
        return newKeySpec(password.toCharArray(), salt);
    }

    private static PBEKeySpec newKeySpec(char[] password, byte[] salt) {
        if (salt == null) {
            // No salt was provided so generate random salt.
            // 32 bits of salt is strong enough for this application.
            salt = new byte[saltSize];
            // There are problem where sRand.nextBytes can 'block' waiting
            // for randomness.
            // The blocking problem was observed on:
            // OpenJDK (IcedTea6 1.8.3) (6b18-1.8.3-2)
            // and
            // The Sun JDK 1.6.0_23-b05
            //
            // Based on docs and discussions, the blocking will only happen
            // when the instance seeds itself, the first time it is used.
            // For this reason, it is better to simply allow SecureRandom to do
            // its
            // own seeding, even if it blocks for a few seconds.
            //
            // It is important to note, however, that each new instance of
            // SecureRandom can incur this seeding latency, so it is important
            // to use singletons or static instances of SecureRandom.
            //
            // We must NOT construct new instances of SecureRandom each time we
            // need
            // random numbers.

            long ts1 = System.currentTimeMillis();
            sRand.nextBytes(salt);
            long latency = System.currentTimeMillis() - ts1;
            if (latency > 2) {
                // WARN log
                say("Blocked for " + latency + " ms on sRand");
            }
        }
        // 8 iterations is best guess, Additional iterations might provide
        // slightly more security, however,
        // performance is a concern here because WSMAN currently authenticates
        // on
        // every message.
        return new PBEKeySpec(password, salt, 8, hashBits);
    }

    // TODO: make this into a JUNIT test.
    void tryout() {
        say("Hello World.");

        for (int i = 0; i < 5; i++) {
            String epass1 = encodePassword("pass1");
            say("epass1:" + epass1);
            String epass2 = encodePassword("pass1");
            say("epass2:" + epass2);

            if (!pwEquals("pass1", epass1)) {
                say("ERROR pass1");
            }
            if (!pwEquals("pass1", epass2)) {
                say("ERROR pass2");
            }
            if (pwEquals("passx", epass1)) {
                say("ERROR passx");
            }
            if (pwEquals("pass1", "2345676789:345353543535"))
                say("lucky1");

            if (pwEquals("pass1", "what:garbage"))
                say("lucky2");

            if (pwEquals("pass1", "0:0"))
                say("lucky3");

            if (pwEquals("pass1", ":02345"))
                say("lucky4");

            if (pwEquals("pass1", "12345678:"))
                say("lucky5");

            if (pwEquals("pass1", "pass1"))
                say("clear equals1");
        }
    }

    // TODO: change callers to do logging.
    static void say(String s) {
        // System.err.println(s);
    }

    public static boolean checkJitcFlagFile() {
        try {
            if (jitcFlagFile.exists() && !jitcFlagFile.isDirectory()) {
                log.debug("[AbstractCipher] JITC flag is on the system");
                return true;
            } else {
                log.debug("[AbstractCipher] JITC flag is NOT on the system");
                return false;
            }
        }catch (Exception e){
            log.error("[AbstractCipher] Cannot access to JITC Flag", e);
            return false;
        }
    }

    public static Cipher getInstanceCipherWrapper(String var0) throws NoSuchPaddingException, NoSuchAlgorithmException,
                                                                      NoSuchProviderException {

        if(CryptoUtils.isJitcFlag())
        {
            return Cipher.getInstance(var0, "BCFIPS");
        }
        else {
            return Cipher.getInstance(var0);
        }
    }

    public static Mac getInstanceMacWrapper(String var0) throws NoSuchPaddingException, NoSuchAlgorithmException,
                                                                NoSuchProviderException {

        if(CryptoUtils.isJitcFlag())
        {
            return Mac.getInstance(var0, "BCFIPS");
        }
        else {
            return Mac.getInstance(var0);
        }
    }
}
