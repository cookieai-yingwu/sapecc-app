package com.veza.app;

import java.util.*;
import java.text.*;
import io.javalin.http.Context;
import io.javalin.http.Handler;
import io.javalin.Javalin;

import io.javalin.community.ssl.SSLPlugin;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.sap.conn.jco.ext.DataProviderException;
import com.sap.conn.jco.ext.DestinationDataEventListener;
import com.sap.conn.jco.ext.DestinationDataProvider;
import com.sap.conn.jco.ext.Environment;

import com.sap.conn.jco.AbapException;
import com.sap.conn.jco.JCoDestination;
import com.sap.conn.jco.JCoDestinationManager;
import com.sap.conn.jco.JCoException;
import com.sap.conn.jco.JCoFunction;
import com.sap.conn.jco.JCoStructure;
import com.sap.conn.jco.JCoTable;

public class App 
{
    private static Logger LOGGER = LoggerFactory.getLogger(App.class);
    static ObjectMapper mapper = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    static InMemoryDestinationDataProvider memoryProvider;

    public static void main( String[] args )
    {
        LOGGER.info("Starting....");

        SSLPlugin plugin = new SSLPlugin(conf -> {
            conf.sniHostCheck = false;
            conf.insecurePort = 9090;
            conf.securePort = 9443;
            conf.http2=false;
            conf.pemFromPath("certjavalin.pem", "keyjavalin.pem", "1234");
          });
        LOGGER.info("Create InMemory DestinationProvider...");
        memoryProvider=new App.InMemoryDestinationDataProvider();
        Environment.registerDestinationDataProvider(memoryProvider);

        PingHandler pingHandler = new PingHandler();
	LockHandler lockHandler = new LockHandler();
        CreateUserHandler createUserHandler = new CreateUserHandler();
 	AssignGroupHandler assignGroupHandler = new AssignGroupHandler();
        // Javalin app = Javalin.create()
        Javalin app = Javalin.create(config -> {
            config.plugins.register(plugin);
        })
            .get("/helloworld", ctx -> ctx.result("Hello World ! Current time:" + getCurrentTimeString()))
            .get("/echo/{text}", ctx -> ctx.result("Echo " + ctx.pathParam("text") +" at " + getCurrentTimeString()))
            .post("/ping", pingHandler)
            .post("/lock", lockHandler)
	    .post("/create_user", createUserHandler)
	    .post("/assign_groups", assignGroupHandler)
	    .start();
    }

    public static String getCurrentTimeString() {
        Date date = new Date();
        SimpleDateFormat dateFormat = new SimpleDateFormat("MM/dd/yyyy HH:mm:ss");
        System.out.println("Get current date time");
        return dateFormat.format(date);
    }

    private static class PingHandler implements Handler {
        @Override 
        public void handle(Context ctx) {
            String body = ctx.body();
            try {
                SapUser sapUser = mapper.readValue(body, SapUser.class);
                if (sapUser.host.isEmpty() || sapUser.client.isEmpty() || sapUser.jcoPassword.isEmpty() 
                    || sapUser.jcoUser.isEmpty() || sapUser.systemNumber.isEmpty() ) {
                    // This is invalid input
                    ctx.result("Invalid sap instance, missing at least one of host,client,systemNumber,jcoUser or jcoPassword");
                    ctx.status(400);
                    return;
                }
                LOGGER.info("Ping " + sapUser);
            
                memoryProvider.changeProperties(sapUser.host, getDestinationPropertiesFromUI(sapUser));
                if (pingDestination(sapUser.host)) {
                    LOGGER.info("Ping OK");
		    ctx.result("OK");
                    ctx.status(200);
                    return;
                }
            } catch (Exception exception) {
                throw new Error(exception);
            }
        }
    }

    private static class CreateUserHandler implements Handler {
        @Override 
        public void handle(Context ctx) { 
            String body = ctx.body();
            try {
                SapUser sapUser = mapper.readValue(body, SapUser.class);
                if (sapUser.host.isEmpty() || sapUser.client.isEmpty() || sapUser.jcoPassword.isEmpty() 
                    || sapUser.jcoUser.isEmpty() || sapUser.systemNumber.isEmpty() ) {
                    // This is invalid input
                    ctx.result("Invalid sap instance, missing at least one of host,client,systemNumber,jcoUser or jcoPassword");
                    ctx.status(400);
                    return;
                }
                LOGGER.info("Create User " + sapUser);
                memoryProvider.changeProperties(sapUser.host, getDestinationPropertiesFromUI(sapUser));
                if (createUser(sapUser.host, sapUser.username, sapUser.password, sapUser.firstName, sapUser.lastName)) {
                    LOGGER.info("Create User OK");
		    ctx.result("{}");
                    ctx.status(200);
                    return;
                }
            } catch (Exception exception) {
                throw new Error(exception);
            }
        }
    }

    private static class AssignGroupHandler implements Handler {
        @Override 
        public void handle(Context ctx) { 
            String body = ctx.body();
            try {
                SapUser sapUser = mapper.readValue(body, SapUser.class);
                if (sapUser.host.isEmpty() || sapUser.client.isEmpty() || sapUser.jcoPassword.isEmpty() 
                    || sapUser.jcoUser.isEmpty() || sapUser.systemNumber.isEmpty() ) {
                    // This is invalid input
                    ctx.result("Invalid sap instance, missing at least one of host,client,systemNumber,jcoUser or jcoPassword");
                    ctx.status(400);
                    return;
                }
                LOGGER.info("Assign group to User " + sapUser);
                memoryProvider.changeProperties(sapUser.host, getDestinationPropertiesFromUI(sapUser));
                if (addUserGroupToUser(sapUser.host, sapUser.username, sapUser.userGroups)) {
                    LOGGER.info("Assign group to user OK!");
		    ctx.result("{}");
                    ctx.status(200);
                    return;
                }
            } catch (Exception exception) {
                throw new Error(exception);
            }
        }
    }

    private static class LockHandler implements Handler {
        @Override 
        public void handle(Context ctx) { 
            String body = ctx.body();
            try {
                SapUser sapUser = mapper.readValue(body, SapUser.class);
                if (sapUser.host.isEmpty() || sapUser.client.isEmpty() || sapUser.jcoPassword.isEmpty() 
                    || sapUser.jcoUser.isEmpty() || sapUser.systemNumber.isEmpty() ) {
                    // This is invalid input
                    ctx.result("Invalid sap instance, missing at least one of host,client,systemNumber,jcoUser or jcoPassword");
                    ctx.status(400);
                    return;
                }
                LOGGER.info("Lock User " + sapUser);
                memoryProvider.changeProperties(sapUser.host, getDestinationPropertiesFromUI(sapUser));
                if (lockUser(sapUser.host, sapUser.username)) {
                    LOGGER.info("Lock user OK");
		    ctx.result("{}");
                    ctx.status(200);
                    return;
                }
            } catch (Exception exception) {
                throw new Error(exception);
            }
        }
    }    

    private static Boolean pingDestination(String destName)
    {
        try {
            JCoDestination destination=JCoDestinationManager.getDestination(destName);
            destination.ping();
            LOGGER.info("Destination "+destName+" works");
            return true;
        } catch (JCoException e) {
            LOGGER.error("Ping destination " + destName + " failed.");
            e.printStackTrace();
            
        }
        return false;
    }

    private static Boolean createUser(String destName, String username, String password, String firstName, String lastName) {
        try {
            JCoDestination destination=JCoDestinationManager.getDestination(destName);
            JCoFunction function=destination.getRepository().getFunction("BAPI_USER_CREATE1");
            if (function==null)
                throw new RuntimeException("BAPI_USER_CREATE1 not found in SAP.");
            function.getImportParameterList().setValue("USERNAME", username);

            function.execute(destination);
            JCoStructure addressData = function.getImportParameterList().getStructure("ADDRESS");
            addressData.setValue("LASTNAME", lastName);
            addressData.setValue("FIRSTNAME", firstName);
            JCoStructure passwordData = function.getImportParameterList().getStructure("PASSWORD");        
            passwordData.setValue("BAPIPWD", password);

            function.execute(destination);
            return processFunctionReturn(function);
        } catch (JCoException e) {
            LOGGER.error("create user " + username + " to " + destName + " failed.");
            e.printStackTrace();
        }
        return false;
    }    

    private static Boolean addUserGroupToUser(String destName, String username, String[] newGroups) {
        try {
            JCoDestination destination=JCoDestinationManager.getDestination(destName);
            JCoFunction functionExisting=destination.getRepository().getFunction("BAPI_USER_GET_DETAIL");
            if (functionExisting==null)
                throw new RuntimeException("BAPI_USER_GET_DETAIL not found in SAP.");
            functionExisting.getImportParameterList().setValue("USERNAME", username);
        
            functionExisting.execute(destination);

            JCoFunction function = destination.getRepository().getFunction("BAPI_USER_ACTGROUPS_ASSIGN");
            if (function==null)
                throw new RuntimeException("BAPI_USER_ACTGROUPS_ASSIGN not found in SAP.");
            JCoTable groups=function.getTableParameterList().getTable("ACTIVITYGROUPS");

            JCoTable existingGroups=functionExisting.getTableParameterList().getTable("ACTIVITYGROUPS");
            for (int i=0; i<existingGroups.getNumRows(); i++)
            {
                existingGroups.setRow(i);
                groups.appendRow();
                groups.setValue("AGR_NAME", existingGroups.getString("AGR_NAME"));
                groups.setValue("FROM_DAT", existingGroups.getDate("FROM_DAT"));
                groups.setValue("TO_DAT", existingGroups.getDate("TO_DAT"));
            }
            for (int j=0;j<newGroups.length;j++) {
                groups.appendRow();
                groups.setValue("AGR_NAME", newGroups[j]);
            }
            function.getImportParameterList().setValue("USERNAME", username);
            function.execute(destination);

            return processFunctionReturn(function);
        } catch (JCoException e) {
            LOGGER.error("add user to gropus for user" + username + " on " + destName + "failed");
            e.printStackTrace();
        }
        return false;
    }

    private static Boolean lockUser(String destName, String username) {
        try {
            JCoDestination destination=JCoDestinationManager.getDestination(destName);
            JCoFunction function=destination.getRepository().getFunction("BAPI_USER_LOCK");
            if (function==null)
                throw new RuntimeException("BAPI_USER_LOCK not found in SAP.");
            function.getImportParameterList().setValue("USERNAME", username);

            function.execute(destination);
            return processFunctionReturn(function);
        } catch (JCoException e) {
            LOGGER.error("lock user " + username + " to " + destName + " failed.");
            e.printStackTrace();
        }
        return false;
    }

    private static Boolean processFunctionReturn(JCoFunction function) {
        JCoTable returns=function.getTableParameterList().getTable("RETURN");
        for (int i=0; i<returns.getNumRows(); i++)
        {
            returns.setRow(i);
            char c = returns.getChar("TYPE");
            if (c == 'S') {
                return true;
            } else {
                LOGGER.error("Return type: " + c + " Message: " + returns.getString("MESSAGE"));
            }
        }
        return false;
    }
    
    private static Properties getDestinationPropertiesFromUI(SapUser sap)
    {
        // adapt parameters in order to configure a valid destination
        Properties connectProperties=new Properties();
        connectProperties.setProperty(DestinationDataProvider.JCO_ASHOST, sap.host);
        connectProperties.setProperty(DestinationDataProvider.JCO_SYSNR, sap.systemNumber);
        connectProperties.setProperty(DestinationDataProvider.JCO_CLIENT, sap.client);
        connectProperties.setProperty(DestinationDataProvider.JCO_USER, sap.jcoUser);
        connectProperties.setProperty(DestinationDataProvider.JCO_PASSWD, sap.jcoPassword);
        // connectProperties.setProperty(DestinationDataProvider.JCO_ASHOST, "hcmsbxas01.sap.digitalriver.com");
        // connectProperties.setProperty(DestinationDataProvider.JCO_SYSNR, "00");
        // connectProperties.setProperty(DestinationDataProvider.JCO_CLIENT, "300");
        // connectProperties.setProperty(DestinationDataProvider.JCO_USER, "DRVEZATEST");
        // connectProperties.setProperty(DestinationDataProvider.JCO_PASSWD, "Veza123!");
        connectProperties.setProperty(DestinationDataProvider.JCO_LANG, "en");
        return connectProperties;
    }   

    private static class SapUser {
        public String host;
        public String systemNumber;
        public String client;
        public String jcoUser;
        public String jcoPassword;

        public String username;
        public String password;
        public String firstName;
        public String lastName;
        public String[] userGroups;

        @Override
        public String toString() {
            String joinUserGroups = "[]";
            if (userGroups != null) {
                joinUserGroups = "["+String.join(",", userGroups)+"]";
            }
            return "{host="+host+", systemNumber="+systemNumber+", client="+client+", jcoUser="+jcoUser+", jcoPassword=*******, username="
                +username+", password=********, firstName="+firstName+", lastName="+lastName+", userGroups="+joinUserGroups+"}";
        }
    }

    private static class InMemoryDestinationDataProvider implements DestinationDataProvider
    {
        private DestinationDataEventListener eL;
        private HashMap<String, Properties> secureDBStorage=new HashMap<String, Properties>();

        @Override
        public Properties getDestinationProperties(String destinationName)
        {
            try
            {
                // read the destination from DB
                Properties p=secureDBStorage.get(destinationName);

                // check if all is correct
                if (p!=null&&p.isEmpty())
                    throw new DataProviderException(DataProviderException.Reason.INVALID_CONFIGURATION,
                            "destination configuration is incorrect", null);

                return p;
            }
            catch (RuntimeException re)
            {
                throw new DataProviderException(DataProviderException.Reason.INTERNAL_ERROR, re);
            }
        }

        @Override
        public void setDestinationDataEventListener(DestinationDataEventListener eventListener)
        {
            this.eL=eventListener;
        }

        @Override
        public boolean supportsEvents()
        {
            return true;
        }

        // implementation that saves the properties in memory
        void changeProperties(String destName, Properties properties)
        {
            synchronized (secureDBStorage)
            {
                if (properties==null)
                {
                    if (secureDBStorage.remove(destName)!=null)
                        eL.deleted(destName);
                }
                else
                {
                    secureDBStorage.put(destName, properties);
                    eL.updated(destName); // create or updated
                }
            }
        }
    } 
}