# Etap 1: Budowanie (Build)
FROM gradle:8-jdk21 AS build
COPY --chown=gradle:gradle . /home/gradle/src
WORKDIR /home/gradle/src
RUN gradle build --no-daemon -x test

# Etap 2: Uruchamianie (Runtime)
FROM eclipse-temurin:21-jre-jammy
WORKDIR /app
COPY --from=build /home/gradle/src/build/libs/*-all.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
