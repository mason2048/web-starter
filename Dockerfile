FROM maven:3-eclipse-temurin-26-alpine@sha256:790e9146c22685eeaf923003fa9a892ce50f22ad06fb998fe861109b1de779c5 AS build

WORKDIR /workspace
COPY . .
RUN --mount=type=cache,target=/root/.m2 \
    mvn -B -ntp -pl web-starter-admin -am package -DskipTests

FROM eclipse-temurin:21-jre-alpine@sha256:3f08b13888f595cc49edabea7250ba69499ba25602b267da591720769400e08c

RUN apk upgrade --no-cache \
    && apk add --no-cache curl \
    && addgroup -S -g 10001 webstarter \
    && adduser -S -D -H -u 10001 -G webstarter -h /app webstarter

WORKDIR /app
COPY --from=build --chown=10001:10001 /workspace/web-starter-admin/target/web-starter-admin-*.jar app.jar

USER 10001:10001
EXPOSE 8080 8081

HEALTHCHECK --interval=20s --timeout=5s --start-period=40s --retries=5 \
    CMD curl -fsS http://127.0.0.1:8081/actuator/health/readiness || exit 1

ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75.0", "-Djava.security.egd=file:/dev/urandom", "-jar", "/app/app.jar"]
