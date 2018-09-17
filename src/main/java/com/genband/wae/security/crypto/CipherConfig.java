/**
 * File Name:   CipherConfig.java
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

/**
 * This is a utility class that maintains cipher configurations
 * 
 * @author MULI
 */
public enum CipherConfig {

    APP_CIPHER("ap", CryptoAlgorithm.AES, CryptoAlgorithm.HmacMD5) {
        @Override
        public String toString() {
            return "app_cipher";
        }
    },
    APP_CIPHER_AES_192("ap2", CryptoAlgorithm.AES_192, CryptoAlgorithm.HmacMD5) {
        @Override
        public String toString() {
            return "app_cipher_aes_192";
        }
    },

    APP_CIPHER_AES_256("ap3", CryptoAlgorithm.AES_256, CryptoAlgorithm.HmacMD5) {
        @Override
        public String toString() {
            return "app_cipher_aes_256";
        }
    },

    FILE_CIPHER("fl", CryptoAlgorithm.AES, CryptoAlgorithm.HmacMD5) {
        @Override
        public String toString() {
            return "file_cipher";
        }
    };

    private String code;
    private CryptoAlgorithm encAlgorithm;
    private CryptoAlgorithm macAlgorithm;

    private CipherConfig(String code, CryptoAlgorithm encAlgorithm, CryptoAlgorithm macAlgorithm) {
        this.code = code;
        this.encAlgorithm = encAlgorithm;
        this.macAlgorithm = macAlgorithm;
    }

    public String getCode() {
        return code;
    }

    public CryptoAlgorithm getEncryptionAlgorithm() {
        return encAlgorithm;
    }

    public CryptoAlgorithm getMACAlgorithm() {
        return macAlgorithm;
    }

    public enum CryptoAlgorithm {
        AES("a01", "default_app_aes_128", 128) {
            @Override
            public String toString() {
                return "AES";
            }
        },
        AES_192("a02", "app_aes_192", 192) {
            @Override
            public String toString() {
                return "AES_192";
            }
        },
        AES_256("a03", "app_aes_256", 256) {
            @Override
            public String toString() {
                return "AES_256";
            }
        },

        HmacMD5("h01", "default_app_hmacmd5_160", 160) {
            @Override
            public String toString() {
                return "HmacMD5";
            }
        };

        private String code;
        private String keyAlias;
        private int keySize;

        private CryptoAlgorithm(String code, String keyAlias, int keySize) {
            this.code = code;
            this.keyAlias = keyAlias;
        }

        public String getCode() {
            return code;
        }

        public String getKeyAlias() {
            return keyAlias;
        }

        public int getKeySize() {
            return keySize;
        }

        public static CryptoAlgorithm getCryptoAlgorithm(int code) {
            for (CryptoAlgorithm cryptoAlgorithm : CryptoAlgorithm.values()) {
                if (cryptoAlgorithm.ordinal() == code) {
                    return cryptoAlgorithm;
                }
            }
            return null;
        }

    }

}
