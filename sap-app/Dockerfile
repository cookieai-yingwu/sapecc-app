FROM adoptopenjdk/maven-openjdk11
WORKDIR /usr/app 

RUN mkdir /usr/app/sap-app

COPY pom.xml /usr/app/sap-app
COPY certjavalin.pem /usr/app/sap-app
COPY keyjavalin.pem /usr/app/sap-app
COPY libsapjco3.so /usr/app/sap-app
COPY sapjco3.jar /usr/app/sap-app

COPY src /usr/app/sap-app/src

WORKDIR /usr/app/sap-app

# If we run mvn clean compile assembly:single locally, we can create container by just copy over jar
# COPY target/sap-app-1.0-SNAPSHOT-jar-with-dependencies.jar /usr/app/sap-app

RUN mvn clean compile assembly:single
RUN cp target/sap-app-1.0-SNAPSHOT-jar-with-dependencies.jar /usr/app/sap-app

ENTRYPOINT java -cp sapjco3.jar:sap-app-1.0-SNAPSHOT-jar-with-dependencies.jar com.veza.app.App
