/**
 * Copyright (c) 2010 GENBAND. All rights reserved.
 * Software owned by or under license with Nortel Networks
 * included in this Release is Copyright  2007-2009 Nortel Networks
 * or its licensors. Use of this software and its contents is subject to the
 * terms and conditions of the applicable end user or software license agreement,
 * right to use notice, and all relevant copyright protections.
 */

package com.genband.wae.security.utils;

import com.genband.logging.userbasedlogger.Logger;
import org.apache.log4j.Level;

/**
 * This class is a Java generic logger wrapper. It checks loggable before logging
 * 
 * @author MULI
 */
public class SecurityLogger {

    private Logger iLogger = null;

    /** constructor */
    private SecurityLogger(String pClassName) {
        iLogger = Logger.getLogger(pClassName);
    }

    /** wrapper builder */
    public static SecurityLogger getLogger(String pClassName) {
        return new SecurityLogger(pClassName);
    }

    /******************** Logging method ********************/

    /**
     * finest, internal log
     * 
     * @param pLogMsg
     */
    public void debug(String pLogMsg) {
        if (iLogger.isEnabledFor(Level.DEBUG)) {
            iLogger.debug(pLogMsg);
        }
    }
    
    /**
     * trace, internal log
     * 
     * @param pLogMsg
     */
    public void trace(String pLogMsg) {
        if (iLogger.isEnabledFor(Level.TRACE)) {
            iLogger.trace(pLogMsg);
        }
    }

    /**
     * info, customer visible
     * 
     * @param pLogMsg
     */
    public void info(String pLogMsg) {
        if (iLogger.isEnabledFor(Level.INFO)) {
            iLogger.info(pLogMsg);
        }
    }

    /**
     * warning, customer visible
     * 
     * @param pLogMsg
     */
    public void warning(String pLogMsg) {
        if (iLogger.isEnabledFor(Level.WARN)) {
            iLogger.warn(pLogMsg);
        }
    }

    /**
     * servere, customer visible
     * 
     * @param pLogMsg
     */
    public void severe(String pLogMsg) {
        if (iLogger.isEnabledFor(Level.FATAL)) {
            iLogger.error(pLogMsg);
        }
    }

    /**
     * Test if it is loggable for given logging level
     * 
     * @param pLogLevel
     * @return
     */
    public boolean isEnabledFor(Level pLogLevel) {
        return iLogger.isEnabledFor(pLogLevel);
    }
}
