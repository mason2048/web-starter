FROM maven:3.9-eclipse-temurin-21-alpine AS build

WORKDIR /workspace
COPY pom.xml ./
COPY web-starter-core/pom.xml web-starter-core/pom.xml
COPY web-starter-system/pom.xml web-starter-system/pom.xml
COPY web-starter-security/pom.xml web-starter-security/pom.xml
COPY web-starter-project/pom.xml web-starter-project/pom.xml
COPY web-starter-mcp/pom.xml web-starter-mcp/pom.xml
COPY web-starter-admin/pom.xml web-starter-admin/pom.xml
RUN mvn -B -ntp -pl web-starter-admin -am dependency:go-offline

COPY web-starter-core web-starter-core
COPY web-starter-system web-starter-system
COPY web-starter-security web-starter-security
COPY web-starter-project web-starter-project
COPY web-starter-mcp web-starter-mcp
COPY web-starter-admin web-starter-admin
RUN mvn -B -ntp -pl web-starter-admin -am package -DskipTests

FROM eclipse-temurin:21-jre-alpine

RUN apk add --no-cache curl \
    && addgroup -S webstarter \
    && adduser -S -G webstarter -h /app webstarter

WORKDIR /app
COPY --from=build /workspace/web-starter-admin/target/web-starter-admin-*.jar app.jar

USER webstarter
EXPOSE 8080

HEALTHCHECK --interval=20s --timeout=5s --start-period=40s --retries=5 \
    CMD curl -fsS http://127.0.0.1:8080/actuator/health/readiness || exit 1

ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75.0", "-Djava.security.egd=file:/dev/urandom", "-jar", "/app/app.jar"]
