package com.genband.logging.userbasedlogger;

import org.apache.log4j.Level;
import org.apache.log4j.MDC;
import org.apache.log4j.Priority;

/**
 * Log4J Logger that is capable of logging user based logs.
 */
public class Logger extends org.apache.log4j.Logger {

    private static LoggerFactory loggerFactory = new LoggerFactory();

    private static final String FQCN = Logger.class.getName();

    private String tierType;

    protected Logger(String name) {
        super(name);
        tierType = getTierType(name);
    }

    public static Logger getLogger(String name) {
        return (Logger) Logger.getLogger(name, loggerFactory);
    }

    public static Logger getLogger(Class clazz) {
        return (Logger) Logger.getLogger(clazz.getName(), loggerFactory);
    }

    @Override
    public void trace(Object message) {
        if (repository.isDisabled(Level.TRACE_INT))
            return;
        if (isGreaterOrEqual(Level.TRACE))
            forcedLog(FQCN, Level.TRACE, message, null);
    }

    @Override
    public void trace(Object message, Throwable t) {
        if (repository.isDisabled(Level.TRACE_INT))
            return;
        if (isGreaterOrEqual(Level.TRACE))
            forcedLog(FQCN, Level.TRACE, message, t);
    }

    @Override
    public void debug(Object message) {
        if (repository.isDisabled(Level.DEBUG_INT))
            return;
        if (isGreaterOrEqual(Level.DEBUG))
            forcedLog(FQCN, Level.DEBUG, message, null);
    }

    @Override
    public void debug(Object message, Throwable t) {
        if (repository.isDisabled(Level.DEBUG_INT))
            return;
        if (isGreaterOrEqual(Level.DEBUG))
            forcedLog(FQCN, Level.DEBUG, message, t);
    }

    @Override
    public void info(Object message) {
        if (repository.isDisabled(Level.INFO_INT))
            return;
        if (isGreaterOrEqual(Level.INFO))
            forcedLog(FQCN, Level.INFO, message, null);
    }

    @Override
    public void info(Object message, Throwable t) {
        if (repository.isDisabled(Level.INFO_INT))
            return;
        if (isGreaterOrEqual(Level.INFO))
            forcedLog(FQCN, Level.INFO, message, t);
    }

    @Override
    public void warn(Object message) {
        if (repository.isDisabled(Level.WARN_INT))
            return;
        if (isGreaterOrEqual(Level.WARN))
            forcedLog(FQCN, Level.WARN, message, null);
    }

    @Override
    public void warn(Object message, Throwable t) {
        if (repository.isDisabled(Level.WARN_INT))
            return;
        if (isGreaterOrEqual(Level.WARN))
            forcedLog(FQCN, Level.WARN, message, t);
    }

    @Override
    public void error(Object message) {
        if (repository.isDisabled(Level.ERROR_INT))
            return;
        if (isGreaterOrEqual(Level.ERROR))
            forcedLog(FQCN, Level.ERROR, message, null);
    }

    @Override
    public void error(Object message, Throwable t) {
        if (repository.isDisabled(Level.ERROR_INT))
            return;
        if (isGreaterOrEqual(Level.ERROR))
            forcedLog(FQCN, Level.ERROR, message, t);
    }

    @Override
    public void fatal(Object message) {
        if (repository.isDisabled(Level.FATAL_INT))
            return;
        if (isGreaterOrEqual(Level.FATAL))
            forcedLog(FQCN, Level.FATAL, message, null);
    }

    @Override
    public void fatal(Object message, Throwable t) {
        if (repository.isDisabled(Level.FATAL_INT))
            return;
        if (isGreaterOrEqual(Level.FATAL))
            forcedLog(FQCN, Level.FATAL, message, t);
    }

    @Override
    public boolean isTraceEnabled() {
        if (repository.isDisabled(Level.TRACE_INT))
            return false;
        return isGreaterOrEqual(Level.TRACE);
    }

    @Override
    public boolean isDebugEnabled() {
        if (repository.isDisabled(Level.DEBUG_INT))
            return false;
        return isGreaterOrEqual(Level.DEBUG);
    }

    @Override
    public boolean isInfoEnabled() {
        if (repository.isDisabled(Level.INFO_INT))
            return false;
        return isGreaterOrEqual(Level.INFO);
    }

    @Override
    public boolean isEnabledFor(Priority level) {
        if (repository.isDisabled(level.toInt()))
            return false;
        return isGreaterOrEqual(level);
    }

    @Override
    public void log(Priority priority, Object message, Throwable t) {
        if (repository.isDisabled(priority.toInt())) {
            return;
        }
        if (isGreaterOrEqual(priority))
            forcedLog(FQCN, priority, message, t);
    }

    @Override
    public void log(String callerFQCN, Priority level, Object message, Throwable t) {
        if (repository.isDisabled(level.toInt())) {
            return;
        }
        if (isGreaterOrEqual(level)) {
            forcedLog(callerFQCN, level, message, t);
        }
    }

    private String getTierType(String name) {
        if (name.contains(LoggerServerProfile.MOBICENTS_CATEGORY_NAME)) {
            return LoggerServerProfile.SLB;
        }
        return System.getProperty(LoggerServerProfile.LOG_SERVER_TYPE);
    }

    public void setTierType(String name) {
        tierType = name;
    }

    private boolean isGreaterOrEqual(Priority level) {
        if (!(LoggerServerProfile.isUserBasedLoggingEnabled())) {
            return (level.isGreaterOrEqual(this.getEffectiveLevel()));
        } else {
            return (level.isGreaterOrEqual(this.getEffectiveLevel()) || isLogLevelAllowedForUser(level));
        }
    }

    private boolean isLogLevelAllowedForUser(Priority level) {
        return LoggerUtil.isLogLevelAllowedForUser((String) MDC.get(LoggerServerProfile.MDC_USER_ID), level, tierType);
    }
}
