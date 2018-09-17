/**
 * Copyright (c) 2010 GENBAND. All rights reserved.
 * Software owned by or under license with Nortel Networks
 * included in this Release is Copyright  2007-2009 Nortel Networks
 * or its licensors. Use of this software and its contents is subject to the
 * terms and conditions of the applicable end user or software license agreement,
 * right to use notice, and all relevant copyright protections.
 */

package com.genband.wae.security.utils;

import org.apache.log4j.Level;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Properties;

/**
 * Database connection utility. This is to initialize connection to database
 * 
 * @author MULI
 */
public class DBConnectionUtils {

    /** Static proerties */
    private static final String PROP_CONN_DB = "wae.mysql.db";
    private static final String PROP_CONN_HOST = "wae.mysql.host";
    private static final String PROP_CONN_PORT = "wae.mysql.port";
    private static final String PROP_CONN_USERNAME = "wae.mysql.user";
    private static final String PROP_CONN_PASSWORD = "wae.mysql.pwd";

    // max number of retries if connection problem happens
    private static final int MAX_TRIAL = 3;

    // JDBC socket timeout value in milliseconds
    // MySQL JDBC Connector reference says,
    // Timeout for socket connect (in milliseconds), with 0 being no
    // timeout. Only works on JDK-1.4 or newer. Defaults to '0'.
    // It seems the MySQL/upbeat failover leads to a JDBC socket connection
    // problem.
    // Set this socket timout to a reasonable value fix the transaction
    // hangs problem and seems working fine
    // set it to 10 seconds for now
    private static final String SOCKET_TIMEOUT = "10000";

    // Query timeout value in seconds
    // According to Java API spec, Statement.setQueryTimeout()
    // sets the number of seconds the driver will wait for a Statement object to
    // execute to the given number of seconds. If the limit is exceeded, an
    // SQLException is thrown.
    private static final int QUERY_TIMEOUT = 10;

    /** Logger */
    private static final SecurityLogger cLogger = SecurityLogger.getLogger(DBConnectionUtils.class.getName());

    /** Load MySQL JDBC driver */
    static {
        try {
            Class lDriver = Class.forName("com.mysql.jdbc.jdbc2.optional.MysqlConnectionPoolDataSource");
        } catch (ClassNotFoundException e) {
            cLogger.severe("SecSvr0000: Failed to load JDBC driver. " + e.getMessage());
        }
    }

    /** Singleton instance */
    private static DBConnectionUtils DBCONN_INSTANCE = null;

    /** JDBC connection */
    private Connection iConn = null;

    /** JDBC connection properties */
    private String iDbUrl = null;
    private String iDbUsername = null;
    private String iDbPassword = null;

    private DBConnectionUtils() {
        String current = null;
        // read&initialize DB connection parameters
        try {

            // Need to build
            // jdbc:mysql://${wae.mysql.host}:${wae.mysql.port}/${wae.mysql.db}
            iDbUrl = "jdbc:mysql://";
            current = PROP_CONN_HOST;
            iDbUrl += System.getProperty(current).toString();
            iDbUrl += ":";
            current = PROP_CONN_PORT;
            iDbUrl += System.getProperty(current).toString();
            iDbUrl += "/";
            current = PROP_CONN_DB;
            iDbUrl += System.getProperty(current).toString();
            current = PROP_CONN_USERNAME;
            iDbUsername = System.getProperty(current).toString();
            current = PROP_CONN_PASSWORD;
            iDbPassword = System.getProperty(current).toString();
            iDbPassword = WaeMysqlPasswordDecoder.decode(iDbPassword);


        } catch (Exception e) {
            cLogger.severe("SecSvr0001: Failed to read security parameters " + current + ". " + e.getMessage());
            throw new RuntimeException("Failed to read database connection properties. " + e.getMessage());
        }

        // initialize connections
        this.getConnection();
    }

    public static DBConnectionUtils getInstance() {
        if (DBCONN_INSTANCE == null) {
            DBCONN_INSTANCE = new DBConnectionUtils();
        }
        return DBCONN_INSTANCE;
    }

    /**
     * Establish connection to db
     * 
     * @return
     * @throws SQLException
     */
    private Connection getConnection() {
        if (cLogger.isEnabledFor(Level.DEBUG)) {
            cLogger.debug("getConnection()");
        }

        try {
            if (iConn == null || iConn.isClosed()) {
                iConn = this.getNewConnection();
            }

            if (cLogger.isEnabledFor(Level.DEBUG)) {
                cLogger.debug("getConnection() done");
            }

            return iConn;
        } catch (SQLException e) {
            cLogger.severe("SecSvr0002: Failed to connect to database! " + e.getMessage());
            throw new RuntimeException("Failed to connect to database. " + e.getMessage());
        }
    }

    /**
     * This is a method that encapsulates database connection and QUERY logic to capture potential connection failures
     * and recover itself
     * 
     * @param pStrStmt
     * @param pParams
     *            Parameters passing into the SQL statement. The order of the parameters in the list must match their
     *            orders in the SQL statement
     * @return
     * @throws Exception
     */
    public ResultSet executeQuery(String pStrStmt, List pParams) throws Exception {
        if (cLogger.isEnabledFor(Level.DEBUG)) {
            cLogger.debug("executeQuery()");
            cLogger.debug("query -- " + pStrStmt);
            cLogger.debug("params -- " + pParams);
        }

        ResultSet lRs = null;
        int i = 0; // numbers of trials
        boolean lSucceed = false;

        // attemp at most 3 times to recover from connection failure or so
        // connection failure may due to database restart, database switch in HA
        // system, or physical connection failure
        while (!lSucceed && i < MAX_TRIAL) {
            try {
                PreparedStatement lPreparedStmt = getConnection().prepareStatement(pStrStmt);
                lPreparedStmt.setQueryTimeout(QUERY_TIMEOUT); // just in case
                                                              // something odd
                                                              // happends
                for (int j = 0; j < pParams.size(); j++) {
                    lPreparedStmt.setObject(j + 1, pParams.get(j)); // SQL
                                                                    // statement
                                                                    // arguments
                                                                    // index
                                                                    // starts
                                                                    // from 1
                }
                lRs = lPreparedStmt.executeQuery();
                lSucceed = true;
            } catch (Exception e) {
                lSucceed = false;
                i++;

                if (cLogger.isEnabledFor(Level.DEBUG)) {
                    cLogger.debug("SecInfo0002: Unexpected failure happened when connecting to database to query/update/delete data. The transaction will be retried. Details -- "
                            + e.getMessage());
                }

                // throw the exception if it has been reached max number of
                // trials
                if (i == MAX_TRIAL) {
                    throw e;
                }
            }
        }

        if (cLogger.isEnabledFor(Level.DEBUG)) {
            cLogger.debug("executeQuery() done");
        }

        return lRs;
    }

    /**
     * This is a method that encapsulates database connection and UPDATE logic to capture potential connection failures
     * and recover itself
     * 
     * @param pStrStmt
     * @param pParams
     *            Parameters passing into the SQL statement. The order of the parameters in the list must match their
     *            orders in the SQL statement
     * @return number of rows updated
     * @throws Exception
     */
    public int executeUpdate(String pStrStmt, List pParams) throws Exception {
        if (cLogger.isEnabledFor(Level.DEBUG)) {
            cLogger.debug("executeUpdate()");
            cLogger.debug("query -- " + pStrStmt);
            cLogger.debug("params -- " + pParams);
        }

        int lUpdatedRowCount = 0;
        int i = 0; // numbers of trials
        boolean lSucceed = false;

        // attemp at most 3 times to recover from connection failure or so
        // connection failure may due to database restart, database switch in HA
        // system, or physical connection failure
        while (!lSucceed && i < MAX_TRIAL) {
            try {
                PreparedStatement lPreparedStmt = getConnection().prepareStatement(pStrStmt);
                lPreparedStmt.setQueryTimeout(QUERY_TIMEOUT); // just in case
                                                              // something odd
                                                              // happends
                for (int j = 0; j < pParams.size(); j++) {
                    lPreparedStmt.setObject(j + 1, pParams.get(j)); // SQL
                                                                    // statement
                                                                    // arguments
                                                                    // index
                                                                    // starts
                                                                    // from 1
                }
                lUpdatedRowCount = lPreparedStmt.executeUpdate();
                lPreparedStmt.close();
                lSucceed = true;
            } catch (Exception e) {
                lSucceed = false;
                i++;

                if (cLogger.isEnabledFor(Level.DEBUG)) {
                    cLogger.debug("SecInfo0002: Unexpected failure happened when connecting to database to query/update/delete data. The transaction will be retried. Details -- "
                            + e.getMessage());
                }

                // throw the exception if it has been reached max number of
                // trials
                if (i == MAX_TRIAL) {
                    throw e;
                }
            }
        }

        if (cLogger.isEnabledFor(Level.DEBUG)) {
            cLogger.debug("executeUpdate() done");
        }

        return lUpdatedRowCount;
    }

    /**
     * This is a method that encapsulates database connection and execute logic to capture potential connection failures
     * and recover itself This method only executes statement with no arguments
     * 
     * @param pStrStmt
     * @param pParams
     *            Parameters passing into the SQL statement. The order of the parameters in the list must match their
     *            orders in the SQL statement
     * @return whether the SQL statement has been executed successfully
     * @throws Exception
     */
    public boolean execute(String pStrStmt) throws Exception {
        if (cLogger.isEnabledFor(Level.DEBUG)) {
            cLogger.debug("execute()");
            cLogger.debug("query -- " + pStrStmt);
        }

        int i = 0; // numbers of trials
        boolean lSucceed = false;

        // attemp at most 3 times to recover from connection failure or so
        // connection failure may due to database restart, database switch in HA
        // system, or physical connection failure
        while (!lSucceed && i < MAX_TRIAL) {
            try {
                PreparedStatement lPreparedStmt = getConnection().prepareStatement(pStrStmt);
                lPreparedStmt.setQueryTimeout(QUERY_TIMEOUT); // just in case
                                                              // something odd
                                                              // happends
                lPreparedStmt.executeUpdate();
                lPreparedStmt.close();
                lSucceed = true;
            } catch (Exception e) {
                lSucceed = false;
                i++;

                if (cLogger.isEnabledFor(Level.DEBUG)) {
                    cLogger.debug("SecInfo0002: Unexpected failure happened when connecting to database to query/update/delete data. The transaction will be retried. Details -- "
                            + e.getMessage());
                }

                // throw the exception if it has been reached max number of
                // trials
                if (i == MAX_TRIAL) {
                    throw e;
                }
            }
        }

        if (cLogger.isEnabledFor(Level.DEBUG)) {
            cLogger.debug("execute() done");
        }

        return lSucceed;
    }

    /*************************
     * Private Helper Methods ************************
     * 
     * @throws SQLException
     */
    private Connection getNewConnection() throws SQLException {
        if (cLogger.isEnabledFor(Level.DEBUG)) {
            cLogger.debug("getNewConnection()");
        }

        // Prepare JDBC connection properties. The properties are JDBC driver
        // specific.
        // In this case, it is MySQL JDBC Connector/J 5.x
        // Please refer to MySQL JDBC Connector reference for details
        // http://dev.mysql.com/doc/refman/5.0/en/connector-j-reference-configuration-properties.html

        Properties lConnProps = new Properties();
        lConnProps.put("user", iDbUsername);
        lConnProps.put("password", iDbPassword);

        // MySQL JDBC Connector reference says,
        // If "autoReconnect" is enabled, the driver will throw an exception for
        // a queries issued on a stale or dead connection, which belong to the
        // current transaction, but will attempt reconnect before the next query
        // issued on the connection in a new transaction.
        // However, this does NOT solve the MySQL/upbeat failover problem.
        lConnProps.put("autoReconnect", "true");

        // MySQL JDBC Connector reference says,
        // Timeout for socket connect (in milliseconds), with 0 being no
        // timeout. Only works on JDK-1.4 or newer. Defaults to '0'.
        // It seems the MySQL/upbeat failover leads to a JDBC socket connection
        // problem.
        // Set this socket timout to a reasonable value fix the transaction
        // hangs problem and seems working fine
        lConnProps.put("socketTimeout", SOCKET_TIMEOUT);

        // get a new connection
        Connection lConn = DriverManager.getConnection(iDbUrl, lConnProps);
        lConn.setAutoCommit(true);

        if (cLogger.isEnabledFor(Level.DEBUG)) {
            cLogger.debug("Connection Established");
        }

        return lConn;
    }

    public static void main(String args[]) {

        DBConnectionUtils.getInstance().getConnection();

    }
}
