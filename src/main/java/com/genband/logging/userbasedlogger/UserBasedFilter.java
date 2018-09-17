package com.genband.logging.userbasedlogger;

import org.apache.log4j.MDC;
import org.apache.log4j.spi.Filter;
import org.apache.log4j.spi.LoggingEvent;

/**
 * Log4J filter that stops certain log messages from being logged, based on the value in MDC and Hazelcast that holds
 * the traced users.
 */
public class UserBasedFilter extends Filter {

    public int decide(LoggingEvent event) {
        if (!(LoggerServerProfile.isUserBasedLoggingEnabled())) {
            return DENY;
        } else {
            if (LoggerUtil.isLogLevelAllowedForUser((String) MDC.get("userId"), event.getLevel(),
                                                    System.getProperty("wae.oam.type"))) {
                return ACCEPT;
            } else {
                return DENY;
            }
        }
    }
}
