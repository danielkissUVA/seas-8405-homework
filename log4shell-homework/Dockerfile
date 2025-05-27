FROM maven:3.8.5-openjdk-8 AS build
WORKDIR /app
COPY . /app/
RUN mvn clean package -DskipTests

FROM openjdk:8-jre-slim
WORKDIR /app
COPY --from=build /app/target/log4shell-demo-0.0.1-SNAPSHOT.jar /app.jar

# Create a startup script inside the container
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Set the script as the ENTRYPOINT
ENTRYPOINT ["docker-entrypoint.sh"]