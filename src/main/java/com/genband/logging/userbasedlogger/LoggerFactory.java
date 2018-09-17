package com.genband.logging.userbasedlogger;

public class LoggerFactory implements org.apache.log4j.spi.LoggerFactory {

    public LoggerFactory() {
    }

    public Logger makeNewLoggerInstance(String name) {
        return new Logger(name);
    }
}
