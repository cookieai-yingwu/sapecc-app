To build locally

> cd sap-app

> mvn clean compile assembly:single

The build webserver will listen on 9443 as the secure port and 9090 as the http port.

To start the webserver locally:

> java -cp sapjco3.jar:sap-app-1.0-SNAPSHOT-jar-with-dependencies.jar com.veza.app.App

Start this server requires the host is a linux based OS system. If the server running on in-compatible OS, it will show the following errors:
Exception in thread "main" java.lang.ExceptionInInitializerError: JCo initialization failed with java.lang.UnsatisfiedLinkError: no sapjco3 in java.library.path: /Users/ywu/Library/Java/Extensions:/Library/Java/Extensions:/Network/Library/Java/Extensions:/System/Library/Java/Extensions:/usr/lib/java:.
	at com.sap.conn.jco.rt.Middleware.<clinit>(Middleware.java:87)
	at com.sap.conn.jco.rt.JCoRuntime.setMiddlewarePropertyValue(JCoRuntime.java:1744)
	at com.sap.conn.jco.rt.DefaultJCoRuntime.initialize(DefaultJCoRuntime.java:88)
	at com.sap.conn.jco.rt.JCoRuntimeFactory.<clinit>(JCoRuntimeFactory.java:23)
    ....

In this case, it need to build a docker container to start the server.
To build the docker image & start container

> docker build --tag <containername_here> .
> docker run -p 9443:9443 -p 9090:9090 <containername_here> 

If the server starts successfully, the following messages will be printed on console 

[main] INFO com.veza.app.App - Starting....
[main] INFO com.veza.app.App - Create InMemory DestinationProvider...
[main] INFO com.veza.app.App - Start Javalin webserver ...
[main] INFO io.javalin.Javalin - Starting Javalin ...
......

[main] INFO io.javalin.Javalin - Javalin started in .....

Now, it is started on localhost with port 9443 as the secure port for https and 9090 as the insecure port for http request.

Try to run a simple API to verify that server is up running 
> curl https://127.0.0.1:9443/about --insecure
or
> curl http://127.0.0.1:9090/about

This should return the hardcode version of the server


Examples of how to interact with the server (in golang) are created in client/goexample/main.go
Once the sap server or the container is up running. Edit the main.go to give a correct username/password/firstname/lastname and usergroups to test. Now run

> go run main.go
