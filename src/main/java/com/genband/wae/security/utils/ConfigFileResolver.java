package com.genband.wae.security.utils;

import org.apache.log4j.Level;

import java.io.File;

/**
 * This is an utility class that computes absolute file name for a given configuration file
 * 
 * @author MULI
 */
public class ConfigFileResolver {

    private static final SecurityLogger cLogger = SecurityLogger.getLogger(ConfigFileResolver.class.getName());

    /**
     * Compute the absolute file name of the configuration file
     * 
     * @param pFileName
     * @return
     */
    public static String getSecurityConfFileName(String pFileName) {
        String name = ConfigFileResolver.class.getClassLoader().getResource(pFileName).getFile().toString();


        return name;
    }
}
