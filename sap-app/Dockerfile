#FROM eclipse-temurin:17-jdk-jammy AS veza-sap-client
FROM adoptopenjdk/maven-openjdk11
WORKDIR /usr/app 

RUN mkdir /usr/app/sap-app

COPY pom.xml /usr/app/sap-app
COPY certjavalin.pem /usr/app/sap-app
COPY keyjavalin.pem /usr/app/sap-app
COPY libsapjco3.so /usr/app/sap-app
COPY sapjco3.jar /usr/app/sap-app

COPY src /usr/app/sap-app

WORKDIR /usr/app/sap-app

# RUN mvn --version
# RUN mvn clean compile assembly:single
# RUN cp target/sap-app-1.0-SNAPSHOT-jar-with-dependencies.jar /usr/app/sap-app

COPY target/sap-app-1.0-SNAPSHOT-jar-with-dependencies.jar /usr/app/sap-app

ENTRYPOINT java -cp sapjco3.jar:sap-app-1.0-SNAPSHOT-jar-with-dependencies.jar com.veza.app.App
