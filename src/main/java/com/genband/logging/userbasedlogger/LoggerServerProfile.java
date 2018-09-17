package com.genband.logging.userbasedlogger;

import org.apache.log4j.Logger;

import java.io.FileInputStream;
import java.util.Properties;

public class LoggerServerProfile {

    public static final String TRUE = "true";
    public static final String FALSE = "false";

    public static final String APP_HOSTS = "wae.app.host_numbers";
    public static final String PRES_HOSTS = "wae.pres.host_numbers";
    public static final String AS_IPC_NET = "as.ipc.net";

    // Used with the HttpDirect mechanism.
    public static final String HOST_NUMBER = "wae.host_number";
    public static final String HOST_NUMBER_DEFAULT = "1";

    public static final String CACHE_MNGR_PORT = "wae.cachemanager.network.port";
    public static final String CACHE_MNGR_PORT_DEFAULT = "31987";
    public static final String USER_BASED_LOGGING_ENABLED = "wae.user.based.logging.enabled";
    public static final boolean USER_BASED_LOGGING_ENABLED_DEFAULT = true;

    public static final String MOBICENTS_CATEGORY_NAME = "org.mobicents";
    public static final String LOG_SERVER_TYPE = "wae.oam.type";

    public static final String APP = "app";
    public static final String PRES = "pres";
    public static final String ADM = "adm";
    public static final String SLB = "slb";

    public static final String MDC_USER_ID = "userId";

    private static final Logger logger = Logger.getLogger(LoggerServerProfile.class);

    private static Properties cachedTierConf = new Properties();
    private static long cachedTierConfTime = 0;
    private static Integer tierConfExpiry = 60000;

    private static final String TIER_CONF = "/opt/wae/profiles/" + System.getProperty("wae.oam.type") + "/conf/";
    private static final String DYNAMIC_PROPERTIES = "wae.dynamic.properties";
    private static final String SLB_TIER_CONF = "/opt/mss/current/sip-balancer/lb-configuration.properties";

    // Hazelcast port number needs to be increased with below to solve hazelcast upgrade problem,
    // Upgraded hazelcast version is 3.8.8
    public static final int CACHE_PORT_PROMOTE_STEP = 10;

    public static String getPresHosts() {
        String tmp = getProperty(PRES_HOSTS);
        if (tmp == null) {
            tmp = System.getProperty(PRES_HOSTS);
            if (tmp == null) {
                logger.warn("Invalid or empty configuration value for " + PRES_HOSTS
                        + " It is set as its default value: NULL ");
            }
        }
        return tmp;
    }

    public static String getHostNumber() {
        String tmp = getProperty(HOST_NUMBER);
        if (tmp == null) {
            tmp = System.getProperty(HOST_NUMBER, HOST_NUMBER_DEFAULT);
            if (tmp == null) {
                logger.warn("Invalid or empty configuration value for " + APP_HOSTS
                        + " It is set as its default value: NULL ");
            }
        }
        return tmp;
    }

    public static String getAsIpcNet() {
        String tmp = getProperty(AS_IPC_NET);
        if (tmp == null) {
            tmp = System.getProperty(AS_IPC_NET);
            if (tmp == null) {
                logger.warn("Invalid or empty configuration value for " + AS_IPC_NET
                        + " It is set as its default value: NULL ");
            }
        }
        return tmp;
    }

    public static int getCacheManagerPort() {
        String tmp = getProperty(CACHE_MNGR_PORT);
        if (tmp == null) {
            tmp = System.getProperty(CACHE_MNGR_PORT, CACHE_MNGR_PORT_DEFAULT);
            if (tmp == null) {
                logger.warn("Invalid or empty configuration value for " + CACHE_MNGR_PORT
                        + " It is set as its default value: " + CACHE_MNGR_PORT_DEFAULT);
            }
        }
        return Integer.parseInt(tmp) + CACHE_PORT_PROMOTE_STEP;
    }

    public static boolean isUserBasedLoggingEnabled() {

        String tmp = System.getProperty(USER_BASED_LOGGING_ENABLED);

        if (tmp != null && !tmp.isEmpty()) {
            if (tmp.equals(TRUE)) {
                return true;
            } else if (tmp.equals(FALSE)) {
                return false;
            }
        }

        logger.debug("Invalid or empty configuration value for " + USER_BASED_LOGGING_ENABLED
                + " It is set as its default value: " + USER_BASED_LOGGING_ENABLED_DEFAULT);
        return USER_BASED_LOGGING_ENABLED_DEFAULT;
    }

    public static String getProperty(String name) {
        long now = System.currentTimeMillis();
        if ((now - cachedTierConfTime) > tierConfExpiry) {
            Properties tmpCache = new Properties();
            try {
                String classPath = LoggerServerProfile.class.getProtectionDomain().getCodeSource().getLocation()
                                                            .getFile();
                if (classPath.contains("sip-balancer")) {
                    tmpCache.load(new FileInputStream(SLB_TIER_CONF));
                } else {
                    tmpCache.load(new FileInputStream(TIER_CONF + DYNAMIC_PROPERTIES));
                }
            } catch (Exception e) {
            }
            if (tmpCache.size() > 0) {
                synchronized (cachedTierConf) {
                    cachedTierConf = tmpCache;
                }
            }
            cachedTierConfTime = now;
        }
        return cachedTierConf.getProperty(name);
    }

}
