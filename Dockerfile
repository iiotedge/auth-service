FROM openjdk:17
COPY target/login-service.jar login-service.jar
ENTRYPOINT ["java", "-jar", "login-service.jar"]
