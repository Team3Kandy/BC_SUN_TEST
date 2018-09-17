package com.genband.wae.security.exception;

/**
 * <p>
 * Copyright (c) 2008 Nortel Networks. All Rights Reserved.
 * </p>
 * <p>
 * NORTEL NETWORKS CONFIDENTIAL. All information, copyrights, trade secrets<br>
 * and other intellectual property rights, contained herein are the property<br>
 * of Nortel Networks. This document is strictly confidential and must not be<br>
 * copied, accessed, disclosed or used in any manner, in whole or in part,<br>
 * without Nortel's express written authorization.
 * </p>
 */

public class CryptoException extends RuntimeException {
    public CryptoException(String pMsg, Exception pCause) {
        super(pMsg + " " + ((pCause != null) ? pCause.getMessage() : ""), pCause);
    }
}
