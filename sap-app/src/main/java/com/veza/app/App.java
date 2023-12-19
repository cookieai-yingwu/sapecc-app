package com.veza.app;

import java.util.*;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.text.*;
import io.javalin.http.Context;
import io.javalin.http.Handler;
import io.javalin.Javalin;

import io.javalin.community.ssl.SSLPlugin;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
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
    public static final String version = "Dec 2023 Build v1.4";
    private static Logger LOGGER = LoggerFactory.getLogger(App.class);
    static List<String> logBuffer = Collections.synchronizedList(new ArrayList<String>());

    SimpleDateFormat df = new SimpleDateFormat("MM/dd/yyyy");
    static ObjectMapper mapper = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    static InMemoryDestinationDataProvider memoryProvider;

    public static void main( String[] args )
    {
        LoggingInfo("Starting....");

        SimpleDateFormat df = new SimpleDateFormat("MM/dd/yyyy");
        mapper.setDateFormat(df);
        SSLPlugin plugin = new SSLPlugin(conf -> {
            conf.sniHostCheck = false;
            conf.insecurePort = 9090;
            conf.securePort = 9443;
            conf.http2=false;
            conf.pemFromPath("certjavalin.pem", "keyjavalin.pem", "1234");
          });
        LoggingInfo("Create InMemory DestinationProvider...");
        memoryProvider=new App.InMemoryDestinationDataProvider();
        Environment.registerDestinationDataProvider(memoryProvider);

        AboutHandler aboutHandler = new AboutHandler();
        RetrieveLogHandler logHandler = new RetrieveLogHandler();

        PingHandler pingHandler = new PingHandler();
        ListUserHandler listUserHandler = new ListUserHandler();
        ListRoleHandler listRoleHandler = new ListRoleHandler();
        LockHandler lockHandler = new LockHandler();
        CreateUserHandler createUserHandler = new CreateUserHandler();
        SyncUserHandler syncUserHandler = new SyncUserHandler();
        AssignGroupHandler assignGroupHandler = new AssignGroupHandler();
        GetUserDetailHandler getUserDetailHandler = new GetUserDetailHandler();
        ModifyUserHandler modifyUserHandler = new ModifyUserHandler();

        LoggingInfo("Start Javalin webserver ...");
        Javalin app = Javalin.create(config -> {
            config.plugins.register(plugin);
        })
            .get("/about", aboutHandler)
            .get("/retrieve_log", logHandler)
            // .get("/echo/{text}", ctx -> ctx.result("Echo " + ctx.pathParam("text") +" at " + getCurrentTimeString()))
            .post("/ping", pingHandler)
            .post("/lock", lockHandler)
	        .post("/create_user", createUserHandler)
            .post("/sync_user", syncUserHandler)
            .post("/modify_user", modifyUserHandler)
	        .post("/assign_groups", assignGroupHandler)
            .post("/user_detail", getUserDetailHandler)
            .post("/list_users", listUserHandler)
            .post("/list_roles", listRoleHandler)
	        .start();
    }

    public static String getCurrentTimeString() {
        Date date = new Date();
        SimpleDateFormat dateFormat = new SimpleDateFormat("MM/dd/yyyy HH:mm:ss");
        return dateFormat.format(date);
    }

    public static void LoggingInfo(final String s) {
        LOGGER.info(s);
        logBuffer.add("SAP INFO :"+s);
        if (logBuffer.size() > 8192) {
            logBuffer.remove(0);
        }
    }

    public static void LoggingError(final String s) {
        LOGGER.error(s);
        logBuffer.add("SAP ERROR :"+s);
        if (logBuffer.size() > 8192) {
            logBuffer.remove(0);
        }
    }

    public static void printStackTrace(Exception ex) {
        StringWriter errors = new StringWriter();
        ex.printStackTrace(new PrintWriter(errors));
        LoggingError(errors.toString());
    }

    public static String[] flushLogBuffer() {
        String[] result = new String[logBuffer.size()];
        for (int i=0;i<logBuffer.size(); i++) {
            result[i] = logBuffer.get(i);
        }
        logBuffer.clear();
        return result;
    }

    private static class AboutHandler implements Handler {
        @Override 
        public void handle(Context ctx) {
            LoggingInfo(getCurrentTimeString() + ": About");
            ctx.result(version);
        }
    }

    private static class RetrieveLogHandler implements Handler {
        @Override
        public void handle(Context ctx) {
            StringBuffer sb = new StringBuffer();
            String[] logs = flushLogBuffer();
            for (int i=0;i<logs.length;i++) {
                sb.append(logs[i] + "\n");
            }
            ctx.result(sb.toString());
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
                LoggingInfo(getCurrentTimeString() + ": Ping " + sapServer);
                if (sapServer.isTestingServer) {
                    ctx.result("{}");
                    ctx.status(200);
                    return;
                }
                synchronized(memoryProvider) {
                    memoryProvider.changeProperties(sapServer.host, getDestinationPropertiesFromStruct(sapServer));
                    String message = pingDestination(sapServer.host);
                    if ("".equals(message)) {
                        LoggingInfo("Ping OK");
                        ctx.result("{}");
                        ctx.status(200);
                        return;
                    } else {
                        LoggingError("Ping Failed: " + message);
                        ctx.result("Failed with message :" + message);
                        ctx.status(500);
                        return;
                    }
                }
            } catch (Exception exception) {
                LoggingError("Failed to ping destination:" + exception.toString());
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
                LoggingInfo(getCurrentTimeString() +": Create User " + sapUser);
                if (sapUser.server.isTestingServer) {
                    SapResult result = new SapResult();
                    if (sapUser.deactivatePassword != null && sapUser.deactivatePassword) {
                        result.newPasswordChanged = false;
                    } else {
                        result.newPasswordChanged = true;
                    }
                    ctx.result(result.toString());
                    ctx.status(200);
                    return;
                }
                synchronized(memoryProvider) {
                    memoryProvider.changeProperties(sapUser.server.host, getDestinationPropertiesFromStruct(sapUser.server));
                    SapResult sapResult = createUser(sapUser.server.host, sapUser.username, sapUser.password, sapUser.firstname, sapUser.lastname,
                        sapUser.department, sapUser.function, sapUser.email, sapUser.licenseType, sapUser.validFrom, sapUser.validTo,
                        sapUser.parameters, sapUser.deactivatePassword);
                    if ("".equals(sapResult.errorMessage)) {
                        LoggingInfo("Create User OK");
                        ctx.result(sapResult.toString());
                        ctx.status(200);
                        return;
                    } else {
                        LoggingError("Create User Failed: " + sapResult.errorMessage);
                        ctx.result("Failed with message :" + sapResult.errorMessage);
                        ctx.status(500);
                        return;
                    }
                }
            } catch (Exception exception) {
                LoggingError("Failed to create user:" + exception.toString());
                ctx.status(500);
                ctx.result(exception.getMessage());
                throw new Error(exception);
            }
        }
    }

    private static class ModifyUserHandler implements Handler {
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
                LoggingInfo(getCurrentTimeString() +": Create User " + sapUser);
                if (sapUser.server.isTestingServer) {
                    SapResult result = new SapResult();
                    if (sapUser.deactivatePassword != null && !sapUser.deactivatePassword && notEmptyString(sapUser.password)) {
                        result.newPasswordChanged = true;
                    } else {
                        result.newPasswordChanged = false;
                    }
                    ctx.result(result.toString());
                    ctx.status(200);
                    return;
                }
                synchronized(memoryProvider) {
                    memoryProvider.changeProperties(sapUser.server.host, getDestinationPropertiesFromStruct(sapUser.server));
                    SapResult sapResult = modifyUser(sapUser.server.host, sapUser.username, sapUser.password, sapUser.firstname, sapUser.lastname,
                        sapUser.department, sapUser.function, sapUser.email, sapUser.licenseType, sapUser.validFrom, sapUser.validTo,
                        sapUser.parameters, sapUser.deactivatePassword);
                    if ("".equals(sapResult.errorMessage)) {
                        LoggingInfo("Modify User OK");
                        ctx.result(sapResult.toString());
                        ctx.status(200);
                        return;
                    } else {
                        LoggingError("Modify User Failed: " + sapResult.errorMessage);
                        ctx.result("Failed with message :" + sapResult.errorMessage);
                        ctx.status(500);
                        return;
                    }
                }
            } catch (Exception exception) {
                LoggingError("Failed to modify user:" + exception.toString());
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
                LoggingInfo(getCurrentTimeString() +": Sync User " + sapUser);
                if (sapUser.server.isTestingServer) {
                    SapResult result = new SapResult();
                    if (sapUser.deactivatePassword != null && !sapUser.deactivatePassword && notEmptyString(sapUser.password)) {
                        result.newPasswordChanged = true;
                    } else {
                        result.newPasswordChanged = false;
                    }
                    ctx.result(result.toString());
                    ctx.status(200);
                    return;
                }
                synchronized(memoryProvider) {
                    memoryProvider.changeProperties(sapUser.server.host, getDestinationPropertiesFromStruct(sapUser.server));
                    SapUserDetail userDetail = getUserDetail(sapUser.server.host, sapUser.username);
                    SapResult sapResult;
                    if (userDetail != null) {
                        LoggingInfo("User "+ sapUser.username +" is existed, modify user");
                        sapResult = modifyUser(sapUser.server.host, sapUser.username, sapUser.password, sapUser.firstname, sapUser.lastname,
                            sapUser.department, sapUser.function, sapUser.email, sapUser.licenseType, sapUser.validFrom, sapUser.validTo,
                            sapUser.parameters, sapUser.deactivatePassword);
                    } else {
                        LoggingInfo("User "+ sapUser.username +" does not existed, create user");
                        sapResult = createUser(sapUser.server.host, sapUser.username, sapUser.password, sapUser.firstname, sapUser.lastname,
                            sapUser.department, sapUser.function, sapUser.email, sapUser.licenseType, sapUser.validFrom, sapUser.validTo,
                            sapUser.parameters, sapUser.deactivatePassword);
                    }
                    if ("".equals(sapResult.errorMessage)) {
                        LoggingInfo("Sync User OK");
                        ctx.result(sapResult.toString());
                        ctx.status(200);
                        return;
                    } else {
                        LoggingError("Sync User Failed: " + sapResult.errorMessage);
                        ctx.result("Failed with message :" + sapResult.errorMessage);
                        ctx.status(500);
                    }
                }
            } catch (Exception exception) {
                LoggingError("Failed to sync user:" + exception.toString());
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
                LoggingInfo(getCurrentTimeString() +": Assign group to User " + request);
                if (request.server.isTestingServer) {
                    ctx.result("{}");
                    ctx.status(200);
                    return;
                }
                synchronized(memoryProvider) {
                    memoryProvider.changeProperties(request.server.host, getDestinationPropertiesFromStruct(request.server));
                    String message = addUserGroupToUser(request.server.host, request.username, request.userGroups);
                    if ("".equals(message)) {
                        LoggingInfo("Assign group to user OK!");
		                ctx.result("{}");
                        ctx.status(200);
                        return;
                    } else {
                        LoggingError("Assign group Failed:"  + message);
                        ctx.result("Failed with message :" + message);
                        ctx.status(500);
                        return;
                    }
                }
            } catch (Exception exception) {
                LoggingError("Failed to assign group:" + exception.toString());
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
                LoggingInfo(getCurrentTimeString() +": Lock User " + request);
                if (request.server.isTestingServer) {
                    ctx.result("{}");
                    ctx.status(200);
                    return;
                }
                synchronized(memoryProvider) {
                    memoryProvider.changeProperties(request.server.host, getDestinationPropertiesFromStruct(request.server));
                    // First remove all activity groups from current user
                    String message = removeParameterAndLicenseTypeAndGroups(request.server.host, request.username);
                    if (!"".equals(message)) {
                        LoggingError("Lock Failed, Unable to remove all roles from a user");
                        ctx.result("Failed with message :" + message);
                        ctx.status(500);
                        return;
                    }
                    message = lockUser(request.server.host, request.username);
                    if ("".equals(message)) {
                        LoggingInfo("Lock user OK");
		                ctx.result("{}");
                        ctx.status(200);
                        return;
                    } else {
                        LoggingError("Lock Failed: " + message);
                        ctx.result("Failed with message :" + message);
                        ctx.status(500);
                        return;
                    }
                }
            } catch (Exception exception) {
                LoggingError("Failed to lock:" + exception.toString());
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
                LoggingInfo(getCurrentTimeString() +": Get User Detail " + request);
                if (request.server.isTestingServer) {
                    ctx.result("{}");
                    ctx.status(200);
                    return;
                }
                synchronized(memoryProvider) {
                    memoryProvider.changeProperties(request.server.host, getDestinationPropertiesFromStruct(request.server));
                    SapUserDetail userDetail = getUserDetail(request.server.host, request.username);
                    if (userDetail != null) {
                        LoggingInfo("Get user detail OK");
		                ctx.result(userDetail.toString());
                        ctx.status(200);
                        return;
                    } else {
                        LoggingError("Get User Detail Failed");
                        ctx.result("Failed");
                        ctx.status(500);
                        return;
                    }
                }
            } catch (Exception exception) {
                LoggingError("Failed to get user detail:" + exception.toString());
                ctx.status(500);
                ctx.result(exception.getMessage());
                throw new Error(exception);
            }
        }
    }

    private static class ListUserHandler implements Handler {
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
                LoggingInfo(getCurrentTimeString() + ": List User " + sapServer);
                if (sapServer.isTestingServer) {
                    List<SapUserSummary> userList = getFakedUserList(sapServer.host);
                    ctx.result(mapper.writeValueAsString(userList));
                    ctx.status(200);
                    return;
                }
                synchronized(memoryProvider) {
                    memoryProvider.changeProperties(sapServer.host, getDestinationPropertiesFromStruct(sapServer));
                    List<SapUserSummary> userList = getUserList(sapServer.host);
                    ctx.result(mapper.writeValueAsString(userList));
                }
            }  catch (Exception exception) {
                LoggingError("Failed to list users:" + exception.toString());
                ctx.status(500);
                ctx.result(exception.getMessage());
                throw new Error(exception);
            }
        }
    }
    
    private static class ListRoleHandler implements Handler {
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
                LoggingInfo(getCurrentTimeString() + ": List Role " + sapServer);
                if (sapServer.isTestingServer) {
                    List<SapRoleSummary> userList = getFakedRoleList(sapServer.host);
                    ctx.result(mapper.writeValueAsString(userList));
                    ctx.status(200);
                    return;
                }
                synchronized(memoryProvider) {
                    memoryProvider.changeProperties(sapServer.host, getDestinationPropertiesFromStruct(sapServer));
                    List<SapRoleSummary> roleList = getRoleList(sapServer.host);
                    ctx.result(mapper.writeValueAsString(roleList));
                }
            }  catch (Exception exception) {
                LoggingError("Failed to list users:" + exception.toString());
                ctx.status(500);
                ctx.result(exception.getMessage());
                throw new Error(exception);
            }
        }
    }

    private static String pingDestination(String destName)
    {
        try {
            JCoDestination destination=JCoDestinationManager.getDestination(destName);
            destination.ping();
            LoggingInfo("Destination "+destName+" works");
            return "";
        } catch (Exception e) {
            LoggingError("Ping destination " + destName + " failed.");
            printStackTrace(e);
            return e.toString();
        }
    }

    private static List<SapRoleSummary> getRoleList(String destName) {
        ArrayList<SapRoleSummary> result = new ArrayList<>();
        try {
            JCoDestination destination=JCoDestinationManager.getDestination(destName);
            JCoFunction function=destination.getRepository().getFunction("PRGN_GET_ROLES");
            if (function==null)
                throw new RuntimeException("PRGN_GET_ROLES  not found in SAP.");
            function.getImportParameterList().setValue("ROLE_NAME_PATTERN", "*");
            function.execute(destination);
            JCoTable groups =function.getTableParameterList().getTable("SINGLE_ROLES");
            for (int i=0;i<groups.getNumRows(); i++) {
                groups.setRow(i);
                SapRoleSummary role = new SapRoleSummary();
                role.name = groups.getString("AGR_NAME");
                result.add(role);
            }
            groups =function.getTableParameterList().getTable("COLLCT_ROLES");
            for (int i=0;i<groups.getNumRows(); i++) {
                groups.setRow(i);
                SapRoleSummary role = new SapRoleSummary();
                role.name = groups.getString("AGR_NAME");
                result.add(role);
            }
            return result;
        } catch (Exception e) {
            LoggingError("RFC_GET_TABLE_ENTRIE to destination " + destName + " failed.");
            printStackTrace(e);
            return result;
        }

    }

    private static List<SapRoleSummary> getFakedRoleList(String destName) {
        SapRoleSummary sapRole = new SapRoleSummary();
        sapRole.name = "SAP_FAKE_USER";
        return Arrays.asList(new SapRoleSummary[]{sapRole});
    }
    
    private static List<SapUserSummary> getFakedUserList(String destName) {
        SapUserSummary sapUser = new SapUserSummary();
        sapUser.username = "FAKEUSER1";
        return Arrays.asList(new SapUserSummary[]{sapUser});
    }

    private static List<SapUserSummary> getUserList(String destName) throws Exception{
        ArrayList<SapUserSummary> result = new ArrayList<>();
        try {
            JCoDestination destination=JCoDestinationManager.getDestination(destName);
            JCoFunction function=destination.getRepository().getFunction("BAPI_USER_GETLIST");
            if (function==null)
                throw new RuntimeException("BAPI_USER_GETLIST not found in SAP.");
            function.execute(destination);
            JCoTable users =function.getTableParameterList().getTable("USERLIST");
            for (int i=0;i<users.getNumRows(); i++) {
                users.setRow(i);
                SapUserSummary sapUser = new SapUserSummary();
                String username = users.getString("USERNAME");
                sapUser.username = username;
                result.add(sapUser);
            }
            return result;
        } catch (Exception e) {
            LoggingError("BAPI_USER_GETLIST to destination " + destName + " failed.");
            printStackTrace(e);
            throw e;
        }
    }

    private static SapResult createUser(String destName, String username, String password, String firstName, String lastName,
        String department, String functionStr, String email, String licenseType, String validFrom, String validTo, Map<String, String> parametersMap, Boolean deactivatePassword) {
        SapResult result = new SapResult();
        if (deactivatePassword != null && deactivatePassword == true) {
            result.newPasswordChanged = false;
        } else {
            result.newPasswordChanged = true;
        }
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

            if ((deactivatePassword != null && deactivatePassword) || notEmptyString(validFrom) || notEmptyString(validTo)) {
                JCoStructure logonData = function.getImportParameterList().getStructure("LOGONDATA");
                if (deactivatePassword != null && deactivatePassword) {
                    logonData.setValue("CODVC", 'X');
                    logonData.setValue("CODVN", 'X');
                }
                if (notEmptyString(validFrom)) {
                    Date validFromDate = getDateFromString(validFrom);
                    if (validFromDate == null) {
                        LoggingError("Invalid format of valid from string: " + validFrom);
                    } else {
                        logonData.setValue("GLTGV", validFromDate);
                    }
                }
                if (notEmptyString(validTo)) {
                    Date validToDate = getDateFromString(validTo);
                    if (validToDate == null) {
                        LoggingError("Invalid format of valid from string: " + validToDate);
                    } else {
                        logonData.setValue("GLTGB", validToDate);
                    }
                }
            }

            function.execute(destination);
            result.errorMessage = processFunctionReturn(function);
            return result;
        } catch (Exception e) {
            LoggingError("create user " + username + " to " + destName + " failed.");
            printStackTrace(e);
            result.errorMessage= e.toString();
            result.newPasswordChanged = false;
            return result;
        }
    }

    private static String addUserGroupToUser(String destName, String username, UserGroup[] newGroups) {
        try {
            JCoDestination destination=JCoDestinationManager.getDestination(destName);
            JCoFunction function = destination.getRepository().getFunction("BAPI_USER_ACTGROUPS_ASSIGN");
            if (function==null)
                throw new RuntimeException("BAPI_USER_ACTGROUPS_ASSIGN not found in SAP.");
            JCoTable groups=function.getTableParameterList().getTable("ACTIVITYGROUPS");

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
        } catch (Exception e) {
            LoggingError("add user to gropus for user" + username + " on " + destName + "failed");
            printStackTrace(e);
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
        } catch (Exception e) {
            LoggingError("lock user " + username + " to " + destName + " failed.");
            printStackTrace(e);
            return e.toString();
        }
    }

    private static String removeParameterAndLicenseTypeAndGroups(String destName, String username) {
        try {
            // Remove all groups from user
            LoggingInfo("Remove all roles from user " + username);
            JCoDestination destination=JCoDestinationManager.getDestination(destName);
            JCoFunction function1 = destination.getRepository().getFunction("BAPI_USER_ACTGROUPS_ASSIGN");
            if (function1==null)
                throw new RuntimeException("BAPI_USER_ACTGROUPS_ASSIGN not found in SAP.");
            JCoTable groups=function1.getTableParameterList().getTable("ACTIVITYGROUPS");
            function1.getImportParameterList().setValue("USERNAME", username);
            function1.execute(destination);
            String message1 = processFunctionReturn(function1);
            if (!"".equals(message1)) {
                LoggingInfo("Unable to remove the roles from user " + username + " error: " + message1);
                return message1;
            }

            LoggingInfo("Remove liense type and parameters from user " + username);
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
        } catch (Exception e) {
            LoggingError("remove user role/license_type and parameters for " + username + " at " + destName + " failed.");
            printStackTrace(e);
            return e.toString();
        }
    }

    private static SapResult modifyUser(String destName, String username, String password, String firstname, String lastname, String department, String functionStr, String email,
        String licenseType, String validFrom, String validTo, Map<String, String> parametersMap, Boolean deactivatePassword) {
    
        SapResult result = new SapResult();    
        // Need special handling if deactivePassword = false and existing user's password is deactivated. we need to notify
        // that a new password is setup
        SapUserDetail userDetail = getUserDetail(destName, username);
        if (deactivatePassword != null && !deactivatePassword && userDetail.deactivatePassword && notEmptyString(password)) {
           LoggingInfo("Currently the user " + username +" is deactivated password, now re generate the password");
           result.newPasswordChanged = true;
        }
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
                    LoggingInfo("Set the parameters type key:" + key + " value: " + parametersMap.get(key));
                }
                // Add change indicator for parameters
                JCoStructure parameterX = function.getImportParameterList().getStructure("PARAMETERX");
                parameterX.setValue("PARID", 'X');
                parameterX.setValue("PARVA", 'X');
            }
            if (deactivatePassword != null || notEmptyString(validFrom) || notEmptyString(validTo)) {
                JCoStructure logonData = function.getImportParameterList().getStructure("LOGONDATA");
                JCoStructure logonDataX = function.getImportParameterList().getStructure("LOGONDATAX");
                if (deactivatePassword != null && deactivatePassword) {
                    logonData.setValue("CODVC", 'X');
                    logonData.setValue("CODVN", 'X');
                    // Add the change indicator for LOGONDATA
                    logonDataX.setValue("CODVC", 'X');
                    logonDataX.setValue("CODVN", 'X');
                } else if (deactivatePassword != null && !deactivatePassword && userDetail.deactivatePassword && notEmptyString(password)) {
                    logonData.setValue("CODVC", 'F');
                    logonData.setValue("CODVN", 'B');
                
                    logonDataX.setValue("CODVC", 'X');
                    logonDataX.setValue("CODVN", 'X');
                    // Also set the new password
                    JCoStructure passwordData = function.getImportParameterList().getStructure("PASSWORD");
                    passwordData.setValue("BAPIPWD", password);
                    JCoStructure passwordDataX = function.getImportParameterList().getStructure("PASSWORDX");
                    passwordDataX.setValue("BAPIPWD", 'X');
                }
                if (notEmptyString(validFrom)) {
                    Date validFromDate = getDateFromString(validFrom);
                    if (validFromDate != null) {
                        logonData.setValue("GLTGV", validFromDate);
                        logonDataX.setValue("GLTGV", 'X');
                    } else {
                        LoggingError("Invalid format of valid from string: " + validFrom);
                    }
                }
                if (notEmptyString(validTo)) {
                    Date validToDate = getDateFromString(validTo);
                    if (validToDate != null) {
                        logonData.setValue("GLTGB", validToDate);
                        logonDataX.setValue("GLTGB", 'X');
                    } else {
                        LoggingError("Invalid format of valid to string: " + validTo);
                    }
                }
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
            result.errorMessage = processFunctionReturn(function);
            return result;
        } catch (Exception e) {
            LoggingError("modify user " + username + " to " + destName + " failed.");
            printStackTrace(e);
            result.errorMessage =  e.toString();
            result.newPasswordChanged = false;
            return result;
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
                LoggingInfo("Unable to understand the return type: " + c);
                return null;
            }
            String expectedMsg = "User " + username + " exists";
            if (infoMessage.toLowerCase().contains(expectedMsg.toLowerCase())) {
                return true;
            }
            LoggingInfo("The info message for checking user " + username + " is: " + infoMessage);
            return false;
        } catch (Exception e) {
            LoggingError("confirm user " + username + " at " + destName + " failed.");
            printStackTrace(e);
            return null;
        }
    }

    // This is a helper func to print a user detail structure (whatever needed for debug)
    private static SapUserDetail getUserDetail(String destName, String username) {
        try {
            JCoDestination destination=JCoDestinationManager.getDestination(destName);
            JCoFunction function=destination.getRepository().getFunction("BAPI_USER_GET_DETAIL");
            if (function==null)
                throw new RuntimeException("BAPI_USER_GET_DETAIL not found in SAP.");
            function.getImportParameterList().setValue("USERNAME", username);
            SapUserDetail result = new SapUserDetail();
            result.username = username;

            function.execute(destination);
            // For a user, print out the license related structure.
            JCoStructure uClass = function.getExportParameterList().getStructure("UCLASS");
            String licType = uClass.getString("LIC_TYPE");
            result.licenseType = licType;

            // Function/Department/Email
            JCoStructure address = function.getExportParameterList().getStructure("ADDRESS");
            String firstname = address.getString("FIRSTNAME");
            result.firstname = firstname;
            String lastname = address.getString("LASTNAME");
            result.lastname = lastname;
            String funcStr = address.getString("FUNCTION");
            result.function = funcStr;
            String departStr = address.getString("DEPARTMENT");
            result.department = departStr;
            String emailStr = address.getString("E_MAIL");
            result.email = emailStr;

            SimpleDateFormat dateFormat = new SimpleDateFormat("MM/dd/yyyy");
            JCoStructure logonData = function.getExportParameterList().getStructure("LOGONDATA");
            Date userValidFromDate = logonData.getDate("GLTGV");
            if (userValidFromDate != null) {
                result.validFrom = dateFormat.format(userValidFromDate);
            }
            Date userValidToDate = logonData.getDate("GLTGB");
            if (userValidToDate != null) {
                result.validTo = dateFormat.format(userValidToDate);
            }
            char codvc = logonData.getChar("CODVC");
            char codvn = logonData.getChar("CODVN");
            if (codvc == 'X' && codvn == 'X') {
                result.deactivatePassword = true;
            }

            Map<String, String> parametersMap = new HashMap<>();
            // Print its table of parameters
            JCoTable parameters=function.getTableParameterList().getTable("PARAMETER");
            for (int i=0;i<parameters.getNumRows(); i++) {
                parameters.setRow(i);
                String parID = parameters.getString("PARID");
                String parValue = parameters.getString("PARVA");
                // String parText = parameters.getString("PARTXT");
                parametersMap.put(parID, parValue);
            }
            if (parametersMap.size() > 0) {
                result.parameters = parametersMap;
            }

            // Get roles
            JCoTable existingGroups=function.getTableParameterList().getTable("ACTIVITYGROUPS");
            int count = existingGroups.getNumRows();
            UserGroup[] userGroups = new UserGroup[count];
            for (int i=0; i<count; i++)
            {
                existingGroups.setRow(i);
                String activityGroupName = existingGroups.getString("AGR_NAME");
                Date fromDate = existingGroups.getDate("FROM_DAT");
                Date toDate = existingGroups.getDate("TO_DAT");
                userGroups[i] = new UserGroup();
                userGroups[i].group = activityGroupName;
                userGroups[i].fromDate = fromDate;
                userGroups[i].toDate = toDate;
            }
            if (userGroups.length >0) {
                result.userGroups = userGroups;
            }
            return result;
        } catch (Exception e) {
            LoggingError("get user detail of " + username + " to " + destName + " failed.");
            printStackTrace(e);
        }
        return null;
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
                LoggingError(errMessage);
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
        public String validFrom;
        public String validTo;

        @Override
        public String toString() {
            return "{server="+server.toString()+", username="+username+", firstName="+firstname+", lastName="+lastname
                   +", department="+department+", function="+function+", email="+email+", validFrom="+validFrom+", validTo="+validTo
                   +", licenseType="+licenseType+", deativatePassword="+deactivatePassword+", paramters="+parameters+"}";
        }
    }

    private static class SapUserSummary {
        public String username;
    }

    private static class SapRoleSummary {
        public String name;
    }

    private static class SapUserDetail {
        public String username;
        public String password;
        public String firstname;
        public String lastname;
        public String department;
        public String function;
        public String email;
        public String licenseType;
        public Map<String, String> parameters;
        public boolean deactivatePassword;
        public String validFrom;
        public String validTo;

        public UserGroup[] userGroups;
        public String toString() {
            try {
                mapper.setSerializationInclusion(Include.NON_NULL);
                return mapper.writeValueAsString(this);
            } catch (JsonProcessingException ex) {
                LoggingError("Unable to serialized SapUserDetail");
                return "{}";
            }
        }
    }

    private static class SapResult {
        public Boolean newPasswordChanged;
        public String errorMessage;
        public String toString() {
            try {
                mapper.setSerializationInclusion(Include.NON_NULL);
                return mapper.writeValueAsString(this);
            } catch (JsonProcessingException ex) {
                LoggingError("Unable to serialized SapUserDetail");
                return "{}";
            }
        }
    }

    public static Date getDateFromString(final String dateString) {
        String[] formatList = new String[]{
            "yyyy-MM-dd",
            "yyyy/MM/dd",
            "MM/dd/yyyy",
            "MM-dd-yyyy",
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            "yyyy-MM-dd'T'HH:mm:ssZ",
            "yyyy-MM-dd'T'HH:mm:ss",
            "yyyy-MM-dd HH:mm:ss",
            "yyyy-MM-dd HH:mm:ssZ"
        };
        for (int i=0;i<formatList.length;i++) {
            Date date = getDateFormStringAndFormat(dateString, formatList[i]);
            if (date != null) {
                return date;
            }
        }
        return null;
    }

    public static Date getDateFormStringAndFormat(final String dateString, final String format) {
        Calendar c1 = Calendar.getInstance();
        c1.set(1900, 0, 1, 0, 0);
        try {
            SimpleDateFormat df = new SimpleDateFormat(format);
            df.setLenient(false);
            Date date = df.parse(dateString);
            if (date.before(c1.getTime())) {
                return null;
            }
            return date;
        } catch (Exception e) {
            return null;
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
