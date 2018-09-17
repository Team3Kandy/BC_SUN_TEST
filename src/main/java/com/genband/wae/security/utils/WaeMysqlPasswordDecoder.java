package com.genband.wae.security.utils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * it is used by DBConnectionUtils to do jdbc connection with encrypted password made by SecureIdentityLoginModule
 */
public final class WaeMysqlPasswordDecoder {

    private WaeMysqlPasswordDecoder(){

    }


    public static String decode(String secret) throws NoSuchPaddingException, NoSuchAlgorithmException,
                                                      InvalidKeyException, BadPaddingException,
                                                      IllegalBlockSizeException {
        byte[] kbytes = "jaas is the way".getBytes();
        SecretKeySpec key = new SecretKeySpec(kbytes, "Blowfish");
        BigInteger n = new BigInteger(secret, 16);
        byte[] encoding = n.toByteArray();
        if (encoding.length % 8 != 0) {
            int length = encoding.length;
            int newLength = (length / 8 + 1) * 8;
            int pad = newLength - length;
            byte[] old = encoding;
            encoding = new byte[newLength];

            for(int i = old.length - 1; i >= 0; --i) {
                encoding[i + pad] = old[i];
            }
        }

        Cipher cipher = Cipher.getInstance("Blowfish");
        cipher.init(2, key);
        byte[] decode = cipher.doFinal(encoding);
        return (new String(decode));
    }


}
