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
    public static final String version = "Dec 2023 Build v1.1";
    private static Logger LOGGER = LoggerFactory.getLogger(App.class);

    SimpleDateFormat df = new SimpleDateFormat("MM/dd/yyyy");
    static ObjectMapper mapper = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    static InMemoryDestinationDataProvider memoryProvider;

    public static void main( String[] args )
    {
        LOGGER.info("Starting....");

        SimpleDateFormat df = new SimpleDateFormat("MM/dd/yyyy");
        mapper.setDateFormat(df);
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

        AboutHandler aboutHandler = new AboutHandler();
        PingHandler pingHandler = new PingHandler();
        LockHandler lockHandler = new LockHandler();
        CreateUserHandler createUserHandler = new CreateUserHandler();
        SyncUserHandler syncUserHandler = new SyncUserHandler();
        AssignGroupHandler assignGroupHandler = new AssignGroupHandler();
        GetUserDetailHandler getUserDetailHandler = new GetUserDetailHandler();

        LOGGER.info("Start Javalin webserver ...");
        Javalin app = Javalin.create(config -> {
            config.plugins.register(plugin);
        })
            .get("/about", aboutHandler)
            // .get("/echo/{text}", ctx -> ctx.result("Echo " + ctx.pathParam("text") +" at " + getCurrentTimeString()))
            .post("/ping", pingHandler)
            .post("/lock", lockHandler)
	        .post("/create_user", createUserHandler)
            .post("/sync_user", syncUserHandler)
	        .post("/assign_groups", assignGroupHandler)
            .post("/user_detail", getUserDetailHandler)
	        .start();
    }

    public static String getCurrentTimeString() {
        Date date = new Date();
        SimpleDateFormat dateFormat = new SimpleDateFormat("MM/dd/yyyy HH:mm:ss");
        return dateFormat.format(date);
    }

    private static class AboutHandler implements Handler {
        @Override 
        public void handle(Context ctx) {
            LOGGER.info(getCurrentTimeString() + ": About");
            ctx.result(version);
        }
    }

    private static class PingHandler implements Handler {
        @Override 
        public void handle(Context ctx) {
            String body = ctx.body();
            try {
                SapServer sapServer = mapper.readValue(body, SapServer.class);
                if (sapServer.host.isEmpty() || sapServer.client.isEmpty() || sapServer.jcoPassword.isEmpty()
                    || sapServer.jcoUser.isEmpty() || sapServer.systemNumber.isEmpty() ) {
                    // This is invalid input
                    ctx.result("Invalid sap instance, missing at least one of host,client,systemNumber,jcoUser or jcoPassword");
                    ctx.status(400);
                    return;
                }
                LOGGER.info(getCurrentTimeString() + ": Ping " + sapServer);
                if (sapServer.isTestingServer) {
                    ctx.status(200);
                    return;
                }
                synchronized(memoryProvider) {
                    memoryProvider.changeProperties(sapServer.host, getDestinationPropertiesFromStruct(sapServer));
                    String message = pingDestination(sapServer.host);
                    if ("".equals(message)) {
                        LOGGER.info("Ping OK");
                        ctx.result("OK");
                        ctx.status(200);
                        return;
                    } else {
                        LOGGER.error("Ping Failed");
                        ctx.result("Failed with message :" + message);
                        ctx.status(500);
                        return;
                    }
                }
            } catch (Exception exception) {
                LOGGER.error("Failed to ping destination:" + exception.toString());
                ctx.status(500);
                ctx.result(exception.getMessage());
                throw new Error(exception);
            }
        }
    }

    private static class CreateUserHandler implements Handler {
        @Override 
        public void handle(Context ctx) { 
            String body = ctx.body();
            try {
                SapCreateUserRequest sapUser = mapper.readValue(body, SapCreateUserRequest.class);
                if (sapUser.server.host.isEmpty() || sapUser.server.client.isEmpty() || sapUser.server.jcoPassword.isEmpty()
                    || sapUser.server.jcoUser.isEmpty() || sapUser.server.systemNumber.isEmpty() ) {
                    // This is invalid input
                    ctx.result("Invalid sap instance, missing at least one of host,client,systemNumber,jcoUser or jcoPassword");
                    ctx.status(400);
                    return;
                }
                LOGGER.info(getCurrentTimeString() +": Create User " + sapUser);
                if (sapUser.server.isTestingServer) {
                    ctx.status(200);
                    return;
                }
                synchronized(memoryProvider) {
                    memoryProvider.changeProperties(sapUser.server.host, getDestinationPropertiesFromStruct(sapUser.server));
                    String message = createUser(sapUser.server.host, sapUser.username, sapUser.password, sapUser.firstname, sapUser.lastname,
                        sapUser.department, sapUser.function, sapUser.email, sapUser.licenseType, sapUser.parameters, sapUser.deactivatePassword);
                    if ("".equals(message)) {
                        LOGGER.info("Create User OK");
                        ctx.result("{}");
                        ctx.status(200);
                        return;
                    } else {
                        LOGGER.error("Create User Failed");
                        ctx.result("Failed with message :" + message);
                        ctx.status(500);
                        return;
                    }
                }
            } catch (Exception exception) {
                LOGGER.error("Failed to create user:" + exception.toString());
                ctx.status(500);
                ctx.result(exception.getMessage());
                throw new Error(exception);
            }
        }
    }

    private static class SyncUserHandler implements Handler {
        @Override
        public void handle(Context ctx) {
            String body = ctx.body();
            try {
                SapCreateUserRequest sapUser = mapper.readValue(body, SapCreateUserRequest.class);
                if (sapUser.server.host.isEmpty() || sapUser.server.client.isEmpty() || sapUser.server.jcoPassword.isEmpty()
                    || sapUser.server.jcoUser.isEmpty() || sapUser.server.systemNumber.isEmpty() ) {
                    // This is invalid input
                    ctx.result("Invalid sap instance, missing at least one of host,client,systemNumber,jcoUser or jcoPassword");
                    ctx.status(400);
                    return;
                }
                LOGGER.info(getCurrentTimeString() +": Sync User " + sapUser);
                if (sapUser.server.isTestingServer) {
                    ctx.status(200);
                    return;
                }
                synchronized(memoryProvider) {
                    Boolean userExisted = confirmUserExist(sapUser.server.host, sapUser.username);
                    if (userExisted == null) {
                        String errMsg = "Unable to determine if user " + sapUser.username +" existsed or not";
                        LOGGER.error(errMsg);
                        ctx.status(500);
                        ctx.result(errMsg);
                        return;
                    }
                    String message = "";
                    if (userExisted) {
                        LOGGER.info("User "+ sapUser.username +" is existed, modify user");
                        message = modifyUser(sapUser.server.host, sapUser.username, sapUser.password, sapUser.firstname, sapUser.lastname,
                            sapUser.department, sapUser.function, sapUser.email, sapUser.licenseType, sapUser.parameters, sapUser.deactivatePassword);
                    } else {
                        LOGGER.info("User "+ sapUser.username +" does not existed, create user");
                        // TODO: verify we have the enough parameters like firstname/lastname, password
                        message = createUser(sapUser.server.host, sapUser.username, sapUser.password, sapUser.firstname, sapUser.lastname,
                            sapUser.department, sapUser.function, sapUser.email, sapUser.licenseType, sapUser.parameters, sapUser.deactivatePassword);
                    }
                    if ("".equals(message)) {
                        LOGGER.info("Sync User OK");
                        ctx.result("{}");
                        ctx.status(200);
                        return;
                    } else {
                        LOGGER.error("Sync User Failed");
                        ctx.result("Failed with message :" + message);
                        ctx.status(500);
                    }
                }
            } catch (Exception exception) {
                LOGGER.error("Failed to sync user:" + exception.toString());
                ctx.status(500);
                ctx.result(exception.getMessage());
                throw new Error(exception);
            }
        }
    }

    private static class AssignGroupHandler implements Handler {
        @Override 
        public void handle(Context ctx) { 
            String body = ctx.body();
            try {
                SapAssignUserGroupRequest request = mapper.readValue(body, SapAssignUserGroupRequest.class);
                if (request.server.host.isEmpty() || request.server.client.isEmpty() || request.server.jcoPassword.isEmpty() 
                    || request.server.jcoUser.isEmpty() || request.server.systemNumber.isEmpty() ) {
                    // This is invalid input
                    ctx.result("Invalid sap instance, missing at least one of host,client,systemNumber,jcoUser or jcoPassword");
                    ctx.status(400);
                    return;
                }
                LOGGER.info(getCurrentTimeString() +": Assign group to User " + request);
                if (request.server.isTestingServer) {
                    ctx.status(200);
                    return;
                }
                synchronized(memoryProvider) {
                    memoryProvider.changeProperties(request.server.host, getDestinationPropertiesFromStruct(request.server));
                    String message = addUserGroupToUser(request.server.host, request.username, request.userGroups);
                    if ("".equals(message)) {
                        LOGGER.info("Assign group to user OK!");
		                ctx.result("{}");
                        ctx.status(200);
                        return;
                    } else {
                        LOGGER.error("Assign group Failed");
                        ctx.result("Failed with message :" + message);
                        ctx.status(500);
                        return;
                    }
                }
            } catch (Exception exception) {
                LOGGER.error("Failed to assign group:" + exception.toString());
                ctx.status(500);
                ctx.result(exception.getMessage());
                throw new Error(exception);
            }
        }
    }

    private static class LockHandler implements Handler {
        @Override 
        public void handle(Context ctx) { 
            String body = ctx.body();
            try {
                SapLockUserRequest request = mapper.readValue(body, SapLockUserRequest.class);
                if (request.server.host.isEmpty() || request.server.client.isEmpty() || request.server.jcoPassword.isEmpty() 
                    || request.server.jcoUser.isEmpty() || request.server.systemNumber.isEmpty() ) {
                    // This is invalid input
                    ctx.result("Invalid sap instance, missing at least one of host,client,systemNumber,jcoUser or jcoPassword");
                    ctx.status(400);
                    return;
                }
                LOGGER.info(getCurrentTimeString() +": Lock User " + request);
                if (request.server.isTestingServer) {
                    ctx.status(200);
                    return;
                }
                synchronized(memoryProvider) {
                    memoryProvider.changeProperties(request.server.host, getDestinationPropertiesFromStruct(request.server));
                    // First remove all activity groups from current user
                    String message = removeParameterAndLicenseTypeAndGroups(request.server.host, request.username);
                    if (!"".equals(message)) {
                        LOGGER.error("Lock Failed, Unable to remove all roles from a user");
                        ctx.result("Failed with message :" + message);
                        ctx.status(500);
                        return;
                    }
                    message = lockUser(request.server.host, request.username);
                    if ("".equals(message)) {
                        LOGGER.info("Lock user OK");
		                ctx.result("{}");
                        ctx.status(200);
                        return;
                    } else {
                        LOGGER.error("Lock Failed");
                        ctx.result("Failed with message :" + message);
                        ctx.status(500);
                        return;
                    }
                }
            } catch (Exception exception) {
                LOGGER.error("Failed to lock:" + exception.toString());
                ctx.status(500);
                ctx.result(exception.getMessage());
                throw new Error(exception);
            }
        }
    }

    private static class GetUserDetailHandler implements Handler {
        @Override
        public void handle(Context ctx) {
            String body = ctx.body();
            try {
                SapUserDetailRequest request = mapper.readValue(body, SapUserDetailRequest.class);
                if (request.server.host.isEmpty() || request.server.client.isEmpty() || request.server.jcoPassword.isEmpty()
                    || request.server.jcoUser.isEmpty() || request.server.systemNumber.isEmpty() ) {
                    // This is invalid input
                    ctx.result("Invalid sap instance, missing at least one of host,client,systemNumber,jcoUser or jcoPassword");
                    ctx.status(400);
                    return;
                }
                LOGGER.info(getCurrentTimeString() +": Get User Detail " + request);
                if (request.server.isTestingServer) {
                    ctx.status(200);
                    return;
                }
                synchronized(memoryProvider) {
                    memoryProvider.changeProperties(request.server.host, getDestinationPropertiesFromStruct(request.server));
                    Boolean exists = confirmUserExist(request.server.host, request.username);
                    if (exists == null || !exists) {
                        LOGGER.error("Get User Detail Failed because user " + request.username + " doesn't exists.");
                        ctx.result("Failed: user doesn't exists");
                        ctx.status(500);
                        return;
                    }
                    // Remove it, this is just for testing.
                    /*Map<String, String> parametersMap = new HashMap<>();
                    parametersMap.put("WLC", "S");
                    String message = modifyUser(request.server.host, request.username, "firstname", "lastname", "depart", "func", "email","91", parametersMap, true);
                    if (!"".equals(message)) {
                        LOGGER.error("Modify user " + request.username + " failed." + message);
                        ctx.result("Modify user failed");
                        ctx.status(500);
                        return;
                    }*/
                    if (getUserDetail(request.server.host, request.username)) {
                        LOGGER.info("Get user detail OK");
		                ctx.result("{}");
                        ctx.status(200);
                        return;
                    } else {
                        LOGGER.error("Get User Detail Failed");
                        ctx.result("Failed");
                        ctx.status(500);
                        return;
                    }
                }
            } catch (Exception exception) {
                throw new Error(exception);
            }
        }
    }

    private static String pingDestination(String destName)
    {
        try {
            JCoDestination destination=JCoDestinationManager.getDestination(destName);
            destination.ping();
            LOGGER.info("Destination "+destName+" works");
            return "";
        } catch (JCoException e) {
            LOGGER.error("Ping destination " + destName + " failed.");
            e.printStackTrace();
            return e.toString();
        }
    }

    private static String createUser(String destName, String username, String password, String firstName, String lastName,
        String department, String functionStr, String email, String licenseType, Map<String, String> parametersMap, Boolean deactivatePassword) {
        try {
            JCoDestination destination=JCoDestinationManager.getDestination(destName);
            JCoFunction function=destination.getRepository().getFunction("BAPI_USER_CREATE1");
            if (function==null)
                throw new RuntimeException("BAPI_USER_CREATE1 not found in SAP.");
            function.getImportParameterList().setValue("USERNAME", username);

            JCoStructure addressData = function.getImportParameterList().getStructure("ADDRESS");
            addressData.setValue("LASTNAME", lastName);
            addressData.setValue("FIRSTNAME", firstName);
            if (notEmptyString(functionStr)) {
                addressData.setValue("FUNCTION", functionStr);
            }
            if (notEmptyString(department)) {
                addressData.setValue("DEPARTMENT", department);
            }
            if (notEmptyString(email)) {
                addressData.setValue("E_MAIL", email);
            }
            JCoStructure passwordData = function.getImportParameterList().getStructure("PASSWORD");        
            passwordData.setValue("BAPIPWD", password);
            if (notEmptyString(licenseType)) {
                JCoStructure uClass = function.getImportParameterList().getStructure("UCLASS");
                uClass.setValue("LIC_TYPE", licenseType);
            }

            if (parametersMap != null && parametersMap.size() > 0) {
                JCoTable parameters=function.getTableParameterList().getTable("PARAMETER");
                for (String key : parametersMap.keySet()) {
                    parameters.appendRow();
                    parameters.setValue("PARID", key);
                    parameters.setValue("PARVA", parametersMap.get(key));
                }
            }

            if (deactivatePassword != null && deactivatePassword) {
                JCoStructure logonData = function.getImportParameterList().getStructure("LOGONDATA");
                logonData.setValue("CODVC", 'X');
                logonData.setValue("CODVN", 'X');
            }

            function.execute(destination);
            return processFunctionReturn(function);
        } catch (JCoException e) {
            LOGGER.error("create user " + username + " to " + destName + " failed.");
            e.printStackTrace();
            return e.toString();
        }
    }

    private static String addUserGroupToUser(String destName, String username, UserGroup[] newGroups) {
        try {
            JCoDestination destination=JCoDestinationManager.getDestination(destName);
            /*JCoFunction functionExisting=destination.getRepository().getFunction("BAPI_USER_GET_DETAIL");
            if (functionExisting==null)
                throw new RuntimeException("BAPI_USER_GET_DETAIL not found in SAP.");
            functionExisting.getImportParameterList().setValue("USERNAME", username);
            functionExisting.execute(destination); */

            JCoFunction function = destination.getRepository().getFunction("BAPI_USER_ACTGROUPS_ASSIGN");
            if (function==null)
                throw new RuntimeException("BAPI_USER_ACTGROUPS_ASSIGN not found in SAP.");
            JCoTable groups=function.getTableParameterList().getTable("ACTIVITYGROUPS");

            /*JCoTable existingGroups=functionExisting.getTableParameterList().getTable("ACTIVITYGROUPS");
            for (int i=0; i<existingGroups.getNumRows(); i++)
            {
                existingGroups.setRow(i);
                groups.appendRow();
                groups.setValue("AGR_NAME", existingGroups.getString("AGR_NAME"));
                groups.setValue("FROM_DAT", existingGroups.getDate("FROM_DAT"));
                groups.setValue("TO_DAT", existingGroups.getDate("TO_DAT"));
            }*/
            if (newGroups != null) {
                for (int j=0;j<newGroups.length;j++) {
                    groups.appendRow();
                    groups.setValue("AGR_NAME", newGroups[j].group);
                    if (newGroups[j].fromDate != null) {
                        groups.setValue("FROM_DAT", newGroups[j].fromDate);
                    }
                    if (newGroups[j].toDate != null) {
                        groups.setValue("TO_DAT", newGroups[j].toDate);
                    }
                }
            }
            function.getImportParameterList().setValue("USERNAME", username);
            function.execute(destination);

            return processFunctionReturn(function);
        } catch (JCoException e) {
            LOGGER.error("add user to gropus for user" + username + " on " + destName + "failed");
            e.printStackTrace();
            return e.toString();
        }
    }

    private static String lockUser(String destName, String username) {
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
            return e.toString();
        }
    }

    private static String removeParameterAndLicenseTypeAndGroups(String destName, String username) {
        try {
            // Remove all groups from user
            LOGGER.info("Remove all roles from user " + username);
            JCoDestination destination=JCoDestinationManager.getDestination(destName);
            JCoFunction function1 = destination.getRepository().getFunction("BAPI_USER_ACTGROUPS_ASSIGN");
            if (function1==null)
                throw new RuntimeException("BAPI_USER_ACTGROUPS_ASSIGN not found in SAP.");
            JCoTable groups=function1.getTableParameterList().getTable("ACTIVITYGROUPS");
            function1.getImportParameterList().setValue("USERNAME", username);
            function1.execute(destination);
            String message1 = processFunctionReturn(function1);
            if (!"".equals(message1)) {
                LOGGER.info("Unable to remove the roles from user " + username + " error: " + message1);
                return message1;
            }

            LOGGER.info("Remove liense type and parameters from user " + username);
            JCoFunction function2 = destination.getRepository().getFunction("BAPI_USER_CHANGE");
            if (function2==null)
                throw new RuntimeException("BAPI_USER_CHANGE not found in SAP.");
            function2.getImportParameterList().setValue("USERNAME", username);
            JCoStructure uClass = function2.getImportParameterList().getStructure("UCLASS");
            uClass.setValue("LIC_TYPE", "");
            // Add the change indicator for uclass
            JCoStructure uClassX = function2.getImportParameterList().getStructure("UCLASSX");
            uClassX.setValue("UCLASS", 'X');
            JCoTable parameters=function2.getTableParameterList().getTable("PARAMETER");
            // Add change indicator for parameters
            JCoStructure parameterX = function2.getImportParameterList().getStructure("PARAMETERX");
            parameterX.setValue("PARID", 'X');
            parameterX.setValue("PARVA", 'X');
            function2.execute(destination);
            return processFunctionReturn(function2);
        } catch (JCoException e) {
            LOGGER.error("lock user " + username + " to " + destName + " failed.");
            e.printStackTrace();
            return e.toString();
        }
    }

    private static String modifyUser(String destName, String username, String password, String firstname, String lastname, String department, String functionStr, String email,
        String licenseType, Map<String, String> parametersMap, Boolean deactivatePassword) {
        try {
            JCoDestination destination=JCoDestinationManager.getDestination(destName);
            JCoFunction function=destination.getRepository().getFunction("BAPI_USER_CHANGE");
            if (function==null)
                throw new RuntimeException("BAPI_USER_CHANGE not found in SAP.");
            function.getImportParameterList().setValue("USERNAME", username);
            if (notEmptyString(licenseType)) {
                JCoStructure uClass = function.getImportParameterList().getStructure("UCLASS");
                uClass.setValue("LIC_TYPE", licenseType);
                // Add the change indicator for uclass
                JCoStructure uClassX = function.getImportParameterList().getStructure("UCLASSX");
                uClassX.setValue("UCLASS", 'X');
                // uClassX.setValue("UCLASSSYS", 'R');
            }
            if (parametersMap != null && parametersMap.size() > 0) {
                JCoTable parameters=function.getTableParameterList().getTable("PARAMETER");
                for (String key : parametersMap.keySet()) {
                    parameters.appendRow();
                    parameters.setValue("PARID", key);
                    parameters.setValue("PARVA", parametersMap.get(key));
                    LOGGER.info("Set the parameters type key:" + key + " value: " + parametersMap.get(key));
                }
                // Add change indicator for parameters
                JCoStructure parameterX = function.getImportParameterList().getStructure("PARAMETERX");
                parameterX.setValue("PARID", 'X');
                parameterX.setValue("PARVA", 'X');
            }
            if (deactivatePassword != null && deactivatePassword) {
                JCoStructure logonData = function.getImportParameterList().getStructure("LOGONDATA");
                logonData.setValue("CODVC", 'X');
                logonData.setValue("CODVN", 'X');
                // Add the change indicator for LOGONDATA
                JCoStructure logonDataX = function.getImportParameterList().getStructure("LOGONDATAX");
                logonDataX.setValue("CODVC", 'X');
                logonDataX.setValue("CODVN", 'X');
            } else if (deactivatePassword != null && !deactivatePassword && notEmptyString(password)) {
                LOGGER.info("Not to deactivate Password");
                JCoStructure logonData = function.getImportParameterList().getStructure("LOGONDATA");
                logonData.setValue("CODVC", 'F');
                logonData.setValue("CODVN", 'B');
                // Add the change indicator for LOGONDATA
                JCoStructure logonDataX = function.getImportParameterList().getStructure("LOGONDATAX");
                logonDataX.setValue("CODVC", 'X');
                logonDataX.setValue("CODVN", 'X');
                // Also set the new password
                JCoStructure passwordData = function.getImportParameterList().getStructure("PASSWORD");
                passwordData.setValue("BAPIPWD", password);
                JCoStructure passwordDataX = function.getImportParameterList().getStructure("PASSWORDX");
                passwordDataX.setValue("BAPIPWD", 'X');
            }

            if (notEmptyString(firstname) || notEmptyString(lastname) || notEmptyString(functionStr) || notEmptyString(department) || notEmptyString(email)) {
                JCoStructure address = function.getImportParameterList().getStructure("ADDRESS");
                JCoStructure addressX = function.getImportParameterList().getStructure("ADDRESSX");
                if (notEmptyString(firstname)) {
                    address.setValue("FIRSTNAME", firstname);
                    addressX.setValue("FIRSTNAME", 'X');
                }
                if (notEmptyString(lastname)) {
                    address.setValue("LASTNAME", firstname);
                    addressX.setValue("LASTNAME", 'X');
                }
                if (notEmptyString(functionStr)) {
                    address.setValue("FUNCTION", functionStr);
                    addressX.setValue("FUNCTION", 'X');
                }
                if (notEmptyString(department)) {
                    address.setValue("DEPARTMENT", department);
                    addressX.setValue("DEPARTMENT", 'X');
                }
                if (notEmptyString(email)) {
                    address.setValue("E_MAIL", email);
                    addressX.setValue("E_MAIL", 'X');
                }
            }

            function.execute(destination);
            return processFunctionReturn(function);
        } catch (JCoException e) {
            LOGGER.error("lock user " + username + " to " + destName + " failed.");
            e.printStackTrace();
            return e.toString();
        }
    }

    private static Boolean confirmUserExist(String destName, String username) {
        try {
            JCoDestination destination=JCoDestinationManager.getDestination(destName);
            JCoFunction function=destination.getRepository().getFunction("BAPI_USER_EXISTENCE_CHECK");
            if (function==null)
                throw new RuntimeException("BAPI_USER_EXISTENCE_CHECK not found in SAP.");
            function.getImportParameterList().setValue("USERNAME", username);

            function.execute(destination);
            // This return is different than all other return in table format used by other API call.
            JCoStructure returnStruct = function.getExportParameterList().getStructure("RETURN");
            char c = returnStruct.getChar("TYPE");
            String infoMessage =  returnStruct.getString("MESSAGE");
            if (c != 'I') {
                LOGGER.info("Unable to understand the return type: " + c);
                return null;
            }
            String expectedMsg = "User " + username + " exists";
            if (infoMessage.toLowerCase().contains(expectedMsg.toLowerCase())) {
                return true;
            }
            LOGGER.info("The info message for checking user " + username + " is: " + infoMessage);
            return false;
        } catch (JCoException e) {
            LOGGER.error("confirm user " + username + " at " + destName + " failed.");
            e.printStackTrace();
            return null;
        }
    }

    // This is a helper func to print a user detail structure (whatever needed for debug)
    private static boolean getUserDetail(String destName, String username) {
        try {
            JCoDestination destination=JCoDestinationManager.getDestination(destName);
            JCoFunction function=destination.getRepository().getFunction("BAPI_USER_GET_DETAIL");
            if (function==null)
                throw new RuntimeException("BAPI_USER_GET_DETAIL not found in SAP.");
            function.getImportParameterList().setValue("USERNAME", username);

            function.execute(destination);
            // For a user, print out the license related structure.
            JCoStructure uClass = function.getExportParameterList().getStructure("UCLASS");
            String licType = uClass.getString("LIC_TYPE");
            LOGGER.info("The lic type is " + licType);

            // Function/Department/Email
            JCoStructure address = function.getExportParameterList().getStructure("ADDRESS");
            String funStr = address.getString("FUNCTION");
            LOGGER.info("The function is " + funStr);
            String departStr = address.getString("DEPARTMENT");
            LOGGER.info("The department is " + departStr);
            String emailStr = address.getString("E_MAIL");
            LOGGER.info("The email is " + emailStr);

            SimpleDateFormat dateFormat = new SimpleDateFormat("MM/dd/yyyy");
            JCoStructure logonData = function.getExportParameterList().getStructure("LOGONDATA");
            Date userValidFromDate = logonData.getDate("GLTGV");
            if (userValidFromDate != null) {
                LOGGER.info("User valid from " + dateFormat.format(userValidFromDate));
            } else {
                LOGGER.info("User valid from field is empty");
            }
            Date userValidToDate = logonData.getDate("GLTGB");
            if (userValidToDate != null) {
                LOGGER.info("User valid to " + dateFormat.format(userValidToDate));
            } else {
                LOGGER.info("User valid to field is empty");
            }
            char usType = logonData.getChar("USTYP");
            LOGGER.info("USTYP:" + usType);
            char codvc = logonData.getChar("CODVC");
            LOGGER.info("CODVC:" + codvc);
            char codvn = logonData.getChar("CODVN");
            LOGGER.info("CODVN:" + codvn);

            // Print its table of parameters
            JCoTable parameters=function.getTableParameterList().getTable("PARAMETER");
            for (int i=0;i<parameters.getNumRows(); i++) {
                parameters.setRow(i);
                String parID = parameters.getString("PARID");
                String parValue = parameters.getString("PARVA");
                String parText = parameters.getString("PARTXT");
                LOGGER.info("parID: " + parID +", parValue: " + parValue + ", parText: " + parText);
            }
            return true;
        } catch (JCoException e) {
            LOGGER.error("get user detail of " + username + " to " + destName + " failed.");
            e.printStackTrace();
        }
        return false;
    }

    private static String processFunctionReturn(JCoFunction function) {
        JCoTable returns=function.getTableParameterList().getTable("RETURN");
        String returnErrorMessage = "";
        for (int i=0; i<returns.getNumRows(); i++)
        {
            returns.setRow(i);
            char c = returns.getChar("TYPE");
            if (c == 'S') {
                return "";
            } else {
                String errMessage = "Return type: " + c + " Message: " + returns.getString("MESSAGE") + ". ";
                LOGGER.error(errMessage);
                returnErrorMessage += errMessage;
            }
        }
        return returnErrorMessage;
    }
    
    private static Properties getDestinationPropertiesFromStruct(SapServer sap)
    {
        // adapt parameters in order to configure a valid destination
        Properties connectProperties=new Properties();
        connectProperties.setProperty(DestinationDataProvider.JCO_ASHOST, sap.host);
        connectProperties.setProperty(DestinationDataProvider.JCO_SYSNR, sap.systemNumber);
        connectProperties.setProperty(DestinationDataProvider.JCO_CLIENT, sap.client);
        connectProperties.setProperty(DestinationDataProvider.JCO_USER, sap.jcoUser);
        connectProperties.setProperty(DestinationDataProvider.JCO_PASSWD, sap.jcoPassword);
        connectProperties.setProperty(DestinationDataProvider.JCO_LANG, "en");
        return connectProperties;
    }

    private static class SapServer {
        public String host;
        public String systemNumber;
        public String client;
        public String jcoUser;
        public String jcoPassword;

        public boolean isTestingServer;

        @Override
        public String toString() {
            return "{host="+host+", systemNumber="+systemNumber+", client="+client+", jcoUser="
                +jcoUser+", jcoPassword=*******, isTestingServer="+(isTestingServer? "true" : "false")+"}";
        }
    }

    public static class SapLockUserRequest {
        public SapServer server;
        public String username;
        @Override
        public String toString() {
            return "{server="+server.toString()+", username="+username+"}";
        }
    }

    public static class SapUserDetailRequest {
        public SapServer server;
        public String username;
        @Override
        public String toString() {
            return "{server="+server.toString()+", username="+username+"}";
        }
    }

    public static class UserGroup {
        public String group;
        public Date fromDate;
        public Date toDate;
        @Override
        public String toString() {
            SimpleDateFormat dateFormat = new SimpleDateFormat("MM/dd/yyyy");
            String fromDateString = "undefined";
            String toDateString = "undefined";
            if (fromDate != null) {
                fromDateString = dateFormat.format(fromDate);
            }
            if (toDate != null) {
                toDateString = dateFormat.format(toDate);
            }
            return group +":{"+fromDateString +":" +toDateString+"}";
        }
    }

    public static class SapAssignUserGroupRequest {
        public SapServer server;
        public String username;
        public UserGroup[] userGroups;
        @Override
        public String toString() {
            String joinUserGroups = "";
            if (userGroups != null) {
                for (int i=0;i< userGroups.length; i++) {
                    if (i > 0) {
                        joinUserGroups += ",";
                    }
                    joinUserGroups += userGroups[i].toString();
                }
            }
            joinUserGroups = "["+ joinUserGroups +"]";
            return "{server="+server.toString()+", username="+username+", userGroups="+joinUserGroups+"}";
        }
    }

    private static class SapCreateUserRequest {
        public SapServer server;

        public String username;
        public String password;
        public String firstname;
        public String lastname;
        public String department;
        public String function;
        public String email;
        public String licenseType;
        public Map<String, String> parameters;
        public Boolean deactivatePassword;

        @Override
        public String toString() {
            return "{server="+server.toString()+", username="+username+", firstName="+firstname+", lastName="+lastname
                   +", department="+department+", function="+function+", email="+email+", licenseType="+licenseType+", deativatePassword="+deactivatePassword+", paramters="+parameters+"}";
        }
    }

    public static boolean notEmptyString( final String s ) {
        // Null-safe, short-circuit evaluation.
        return s != null && s.trim().length()>0;
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
