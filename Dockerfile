FROM maven:3-eclipse-temurin-24-alpine@sha256:1e5a24dab38f3160d404439891ad4fd9b7e14b9e3c5bf65e3a953ba7d6ab4e8e AS build

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
