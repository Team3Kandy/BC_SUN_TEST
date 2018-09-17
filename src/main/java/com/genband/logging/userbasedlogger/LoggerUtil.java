package com.genband.logging.userbasedlogger;

import org.apache.log4j.Level;
import org.apache.log4j.Priority;

import java.util.Map;

public class LoggerUtil {
    private static final Logger logger = Logger.getLogger(LoggerUtil.class);

    private LoggerUtil() {

    }

    public static boolean isLogLevelAllowedForUser(String mdcUserId, Priority logLevel, String tierType) {

        return false;
    }
}
